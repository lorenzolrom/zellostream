import sys
import subprocess
import websocket
import socket
import json
import time
import logging
import shlex
import pyaudio
from numpy import frombuffer, array, repeat, short, concatenate
import opuslib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
from threading import Thread, RLock, Event, Timer
import queue
import os
import soxr
import serial

logging.basicConfig(format='%(asctime)s %(levelname).1s %(funcName)s: %(message)s', level=logging.INFO)
LOG = logging.getLogger('Zellostream')

CHUNK_SECONDS = 0.06  # 60ms per audio chunk, matches Zello's packet duration
MAX_QUEUE_SECONDS = 2.0  # cap on how much audio we'll buffer before dropping the oldest

if os.name != 'nt':  # 'nt' is Windows
    try:
        from pulseaudio import PulseAudioHandler
    except Exception:
        PulseAudioHandler = None

"""On Windows, requires these DLL files in the same directory:
opus.dll (renamed from libopus-0.dll)
libwinpthread-1.dll
libgcc_s_sjlj-1.dll
These can be obtained from the 'opusfile' download at http://opus-codec.org/downloads/
"""

seq_num = 0


class ConfigException(Exception):
    pass


class Resampler:
    """Stateful mono int16 resampler. Keeps filter state across chunks so
    streaming audio doesn't click at chunk boundaries, and is cheap enough
    to run on every 60ms chunk (unlike a stateless per-chunk resample)."""

    def __init__(self, in_rate, out_rate):
        self.enabled = in_rate != out_rate
        if self.enabled:
            self._stream = soxr.ResampleStream(in_rate, out_rate, 1, dtype='int16', quality='HQ')

    def process(self, data):
        if not self.enabled or len(data) == 0:
            return data.astype(short)
        return self._stream.resample_chunk(data.astype(short), last=False).astype(short)


class FrameAccumulator:
    """Buffers variable-length audio into exact fixed-size frames. A
    streaming resampler doesn't emit exactly frame_size samples on every
    call (FIR group delay shifts samples between calls), but the Opus
    encoder requires an exact frame_size match or it reads garbage/drops
    samples from its raw pcm buffer."""

    def __init__(self, frame_size):
        self.frame_size = frame_size
        self._buf = array([], dtype=short)

    def push(self, data):
        if len(data):
            self._buf = concatenate([self._buf, data.astype(short)]) if len(self._buf) else data.astype(short)
        frames = []
        while len(self._buf) >= self.frame_size:
            frames.append(self._buf[:self.frame_size])
            self._buf = self._buf[self.frame_size:]
        return frames


def get_config():
    config = {}

    with open("config.json") as f:
        configdata = json.load(f)

    username = configdata.get("username")
    if not username:
        raise ConfigException("ERROR GETTING USERNAME FROM CONFIG FILE")
    config["username"] = username
    password = configdata.get("password")
    if not password:
        raise ConfigException("ERROR GETTING PASSWORD FROM CONFIG FILE")
    config["password"] = password
    zello_channel = configdata.get("zello_channel")
    if not zello_channel:
        raise ConfigException("ERROR GETTING ZELLO CHANNEL NAME FROM CONFIG FILE")
    config["zello_channel"] = zello_channel
    config["vox_silence_time"] = configdata.get("vox_silence_time", 3)
    config["audio_threshold"] = configdata.get("audio_threshold", 1000)
    config["input_device_index"] = configdata.get("input_device_index", 0)
    config["input_pulse_name"] = configdata.get("input_pulse_name")
    config["output_device_index"] = configdata.get("output_device_index", 0)
    config["output_pulse_name"] = configdata.get("output_pulse_name")
    config["audio_input_sample_rate"] = configdata.get("audio_input_sample_rate", 48000)
    config["audio_input_channels"] = configdata.get("audio_input_channels", 1)
    config["zello_sample_rate"] = configdata.get("zello_sample_rate", 16000)
    config["audio_output_sample_rate"] = configdata.get("audio_output_sample_rate", 48000)
    config["audio_output_channels"] = configdata.get("audio_output_channels", 1)
    config["audio_output_volume"] = configdata.get("audio_output_volume", 1)
    config["in_channel_config"] = configdata.get("in_channel", "mono")
    config["audio_source"] = configdata.get("audio_source", "Sound Card")
    config["ptt_on_command"] = configdata.get("ptt_on_command")
    config["ptt_off_command"] = configdata.get("ptt_off_command")
    config["ptt_off_delay"] = configdata.get("ptt_off_delay", 2)
    config["ptt_command_support"] = not (config["ptt_on_command"] is None or config["ptt_off_command"] is None)
    config["logging_level"] = configdata.get("logging_level", "warning")
    config["udp_port"] = configdata.get("UDP_PORT", 9123)
    config["tgid_in_stream"] = configdata.get("TGID_in_stream", False)
    config["tgid_to_play"] = configdata.get("TGID_to_play", 70000)
    config["ptt_serial_port"] = configdata.get("ptt_serial_port")  # e.g., "/dev/ttyUSB0" or "COM3"
    config["ptt_rts_invert"] = configdata.get("ptt_rts_invert", False)  # True if your interface wants RTS low for PTT
    config["ptt_serial_support"] = config["ptt_serial_port"] is not None
    config["cor_serial_port"] = configdata.get("cor_serial_port")  # optional; when set, use CTS instead of VOX
    config["cor_cts_invert"] = configdata.get("cor_cts_invert", False)  # invert CTS logic if needed
    config["cor_cts_debounce_ms"] = int(configdata.get("cor_cts_debounce_ms", 30))

    # Zello WS URL & auth
    zello_work = configdata.get("zello_work_account_name")
    if zello_work:
        config["zello_ws_url"] = "wss://zellowork.io/ws/" + zello_work
    else:
        config["zello_ws_url"] = "wss://zello.io/ws"

        issuer = configdata.get("issuer")
        if not issuer:
            raise ConfigException("ERROR GETTING ZELLO ISSUER ID FROM CONFIG FILE")
        config["issuer"] = issuer

        with open("privatekey.pem", "r") as f:
            config["key"] = RSA.import_key(f.read())
    return config


def create_zello_jwt(config):
    # Create a Zello-specific JWT.  Can't use PyJWT because Zello doesn't support url safe base64 encoding in the JWT.
    header = {"typ": "JWT", "alg": "RS256"}
    payload = {"iss": config["issuer"], "exp": round(time.time() + 60)}
    signer = pkcs1_15.new(config["key"])
    json_header = json.dumps(header, separators=(",", ":"), cls=None).encode("utf-8")
    json_payload = json.dumps(payload, separators=(",", ":"), cls=None).encode("utf-8")
    h = SHA256.new(base64.standard_b64encode(json_header) + b"." + base64.standard_b64encode(json_payload))
    signature = signer.sign(h)
    jwt = base64.standard_b64encode(json_header) + b"." + base64.standard_b64encode(
        json_payload) + b"." + base64.standard_b64encode(signature)
    return jwt


def get_default_input_audio_index(config, p):
    info = p.get_host_api_info_by_index(0)
    numdevices = info.get('deviceCount')
    input_device_names = {}
    for i in range(0, numdevices):
        if p.get_device_info_by_host_api_device_index(0, i).get('maxInputChannels') > 0:
            device_info = p.get_device_info_by_host_api_device_index(0, i)
            input_device_names[device_info["name"]] = device_info["index"]
    return input_device_names.get("default", config["input_device_index"])


def get_default_output_audio_index(config, p):
    info = p.get_host_api_info_by_index(0)
    numdevices = info.get('deviceCount')
    output_device_names = {}
    for i in range(0, numdevices):
        if p.get_device_info_by_host_api_device_index(0, i).get('maxOutputChannels') > 0:
            device_info = p.get_device_info_by_host_api_device_index(0, i)
            output_device_names[device_info["name"]] = device_info["index"]
    return output_device_names.get("default", config["output_device_index"])


def start_audio(config, p):
    audio_chunk = int(config["audio_input_sample_rate"] * 0.06)  # 60ms = 960 samples @ 16000 S/s
    format = pyaudio.paInt16
    LOG.debug("open audio")
    if (config["input_pulse_name"] != None or config[
        "output_pulse_name"] != None) and os.name != 'nt':  # using pulseaudio
        if PulseAudioHandler is None:
            raise RuntimeError("PulseAudio support requested but pulsectl/libpulse is unavailable")
        pulse = PulseAudioHandler()
    # Audio input
    if config["input_pulse_name"] != None and os.name != 'nt':  # using pulseaudio for input
        input_device_index = get_default_input_audio_index(config, p)  # get default device first
    else:  # use pyaudio device number
        input_device_index = config["input_device_index"]
    input_stream = p.open(
        format=format,
        channels=config["audio_input_channels"],
        rate=config["audio_input_sample_rate"],
        input=True,
        frames_per_buffer=audio_chunk * 2,  # Increase buffer for lower spec devices
        input_device_index=input_device_index,
    )
    LOG.debug("audio input opened")
    if config["input_pulse_name"] != None and os.name != 'nt':  # redirect input to zellostream with pulseaudio
        LOG.error("input_pulse_name is %s", config["input_pulse_name"])
        pulse_source_index = pulse.get_source_index(config["input_pulse_name"])
        pulse_source_output_index = pulse.get_own_source_output_index()
        if pulse_source_index is None or pulse_source_output_index is None:
            LOG.warning(
                "cannot move source output %d to source %d",
                pulse_source_output_index,
                pulse_source_index
            )
        else:
            try:
                pulse.move_source_output(pulse_source_output_index, pulse_source_index)
                LOG.debug(
                    "moved pulseaudio source output %d to source %d",
                    pulse_source_output_index,
                    pulse_source_index
                )
            except Exception as ex:
                LOG.error("exception assigning pulseaudio source: %s", ex)
    # Audio outpput
    if config["output_pulse_name"] != None and os.name != 'nt':  # using pulseaudio for output
        output_device_index = get_default_output_audio_index(config, p)
    else:  # use pyaudio device number
        output_device_index = config["output_device_index"]
    output_stream = p.open(
        format=format,
        channels=config["audio_output_channels"],
        rate=config["audio_output_sample_rate"],
        output=True,
        frames_per_buffer=audio_chunk,
        output_device_index=output_device_index,
    )
    LOG.debug("audio output opened")
    if config["output_pulse_name"] != None and os.name != 'nt':  # redirect output from zellostream with pulseaudio
        LOG.error("output_pulse_name is %s", config["output_pulse_name"])
        pulse_sink_index = pulse.get_sink_index(config["output_pulse_name"])
        pulse_sink_input_index = pulse.get_own_sink_input_index()
        if pulse_sink_index is None or pulse_sink_input_index is None:
            LOG.warning(
                "cannot move pulseaudio sink input %d to sink %d",
                pulse_sink_input_index,
                pulse_sink_index
            )
        else:
            try:
                pulse.move_sink_input(pulse_sink_input_index, pulse_sink_index)
                LOG.debug(
                    "moved pulseaudio sink input %d to sink %d",
                    pulse_sink_input_index,
                    pulse_sink_index
                )
            except Exception as ex:
                LOG.error("exception assigning pulseaudio sink: %s", ex)
    return input_stream, output_stream


def start_output_audio(config, p):
    audio_chunk = int(config["audio_input_sample_rate"] * 0.06)
    format = pyaudio.paInt16
    if config["output_pulse_name"] is not None and os.name != 'nt':
        if PulseAudioHandler is None:
            raise RuntimeError("PulseAudio output requested but pulsectl/libpulse is unavailable")
        pulse = PulseAudioHandler()
        output_device_index = get_default_output_audio_index(config, p)
    else:
        pulse = None
        output_device_index = config["output_device_index"]

    output_stream = p.open(
        format=format,
        channels=config["audio_output_channels"],
        rate=config["audio_output_sample_rate"],
        output=True,
        frames_per_buffer=audio_chunk,
        output_device_index=output_device_index,
    )

    if pulse is not None:
        pulse_sink_index = pulse.get_sink_index(config["output_pulse_name"])
        pulse_sink_input_index = pulse.get_own_sink_input_index()
        if pulse_sink_index is None or pulse_sink_input_index is None:
            LOG.warning(
                "cannot move pulseaudio sink input %d to sink %d",
                pulse_sink_input_index,
                pulse_sink_index
            )
        else:
            try:
                pulse.move_sink_input(pulse_sink_input_index, pulse_sink_index)
            except Exception as ex:
                LOG.error("exception assigning pulseaudio sink: %s", ex)

    return output_stream


def _select_channel(data, input_channels, channel):
    if input_channels <= 1 or len(data) == 0:
        return data
    frames = data.reshape(-1, input_channels)
    if channel == "left":
        return frames[:, 0]
    elif channel == "right":
        return frames[:, 1]
    elif channel in ("mix", "mono"):
        return frames.mean(axis=1)
    else:
        return frames[:, 0]


def record_chunk(config, stream, resampler, channel="mono"):
    audio_chunk = int(config["audio_input_sample_rate"] * CHUNK_SECONDS)
    data = stream.read(audio_chunk, exception_on_overflow=False)  # Remove exception for lower spec devices
    data = frombuffer(data, dtype=short)

    input_channels = max(1, int(config.get("audio_input_channels", 1)))
    zello_data = _select_channel(data, input_channels, channel)
    return resampler.process(zello_data)


def udp_rx(sock, config):
    global udpdata
    max_bytes = int(MAX_QUEUE_SECONDS * config["audio_input_sample_rate"] * 2 *
                     max(1, int(config.get("audio_input_channels", 1))))
    last_drop_warn = 0.0
    while processing:
        try:
            newdata, addr = sock.recvfrom(4096)
            if config['tgid_in_stream']:
                if len(newdata) > 0:
                    tgid = int.from_bytes(newdata[0:4], "little")
                    LOG.debug("got %d bytes from %s for TGID %d", len(newdata), addr, tgid)
                    if tgid == config['tgid_to_play']:
                        newdata = newdata[4:]
                    else:
                        newdata = b''
            else:
                if len(newdata) > 0:
                    LOG.debug("got %d bytes from %s", len(newdata), addr)
            with udp_buffer_lock:
                udpdata = udpdata + newdata
                overflow = len(udpdata) - max_bytes
                if overflow > 0:
                    udpdata = udpdata[overflow:]
                    now = time.time()
                    if now - last_drop_warn > 1.0:
                        LOG.warning("UDP input buffer overflowed, dropping oldest audio (consumer too slow)")
                        last_drop_warn = now
        except socket.timeout:
            pass


def get_udp_audio(config, resampler, seconds, channel="mono"):
    global udpdata
    input_channels = max(1, int(config.get("audio_input_channels", 1)))
    num_bytes = int(seconds * config["audio_input_sample_rate"] * 2 * input_channels)
    with udp_buffer_lock:
        data = frombuffer(udpdata[:num_bytes], dtype=short)
        if len(data) == num_bytes / 2:
            udpdata = udpdata[num_bytes:]
        else:
            data = array([], dtype=short)
    zello_data = _select_channel(data, input_channels, channel)
    return resampler.process(zello_data)


_seq_lock = RLock()


def next_seq():
    global seq_num
    with _seq_lock:
        seq_num += 1
        return seq_num


class PendingReply:
    """Single-slot mailbox the reader thread uses to hand a control-message
    reply (e.g. the response to start_stream) back to whichever thread is
    waiting on it. Only one request is ever in flight at a time."""

    def __init__(self):
        self._event = Event()
        self._data = None
        self._active = False

    def arm(self):
        self._data = None
        self._event.clear()
        self._active = True

    def disarm(self):
        self._active = False

    def is_active(self):
        return self._active

    def fulfill(self, data):
        self._data = data
        self._event.set()

    def wait(self, timeout):
        got = self._event.wait(timeout)
        self._event.clear()
        return self._data if got else None


class ZelloConnection:
    """Wraps the websocket connection. All sends go through here (guarded by
    a lock so the TX thread's audio/control sends can't interleave badly);
    only the reader thread ever calls recv() on the underlying socket, so
    RX and TX can run concurrently without racing on the same connection."""

    def __init__(self, config):
        self.config = config
        self.ws = None
        self._connect_lock = RLock()
        self.connected = Event()

    def connect(self):
        with self._connect_lock:
            if self.connected.is_set():
                return True
            global seq_num
            try:
                ws = websocket.create_connection(self.config["zello_ws_url"])
                ws.settimeout(1)
                seq_num = 1
                send = {"command": "logon", "seq": seq_num}
                if "zellowork" not in self.config["zello_ws_url"]:
                    encoded_jwt = create_zello_jwt(self.config)
                    send["auth_token"] = encoded_jwt.decode("utf-8")
                send["username"] = self.config["username"]
                send["password"] = self.config["password"]
                send["channel"] = self.config["zello_channel"]
                ws.send(json.dumps(send))
                result = ws.recv()
                data = json.loads(result)
                if data.get("error"):
                    LOG.error("zello logon failed: %s", data.get("error"))
                    try:
                        ws.close()
                    except Exception:
                        pass
                    return False
                LOG.info("seq: %d", data.get("seq"))
                seq_num += 1
                ws.settimeout(0.5)
                self.ws = ws
                self.connected.set()
                return True
            except Exception as ex:
                LOG.error("exception: %s", ex)
                return False

    def mark_disconnected(self):
        with self._connect_lock:
            if not self.connected.is_set():
                return
            self.connected.clear()
            ws, self.ws = self.ws, None
        if ws:
            try:
                ws.close()
            except Exception:
                pass

    def send_json(self, payload):
        ws = self.ws
        if ws is None or not self.connected.is_set():
            raise ConnectionError("not connected")
        ws.send(json.dumps(payload))

    def send_binary(self, data):
        ws = self.ws
        if ws is None or not self.connected.is_set():
            raise ConnectionError("not connected")
        return ws.send_binary(data)

    def recv(self, timeout):
        ws = self.ws
        if ws is None or not self.connected.is_set():
            raise ConnectionError("not connected")
        ws.settimeout(timeout)
        return ws.recv()


def start_stream(config, conn, pending):
    send = {
        "command": "start_stream",
        "channel": config["zello_channel"],
        "type": "audio",
        "codec": "opus",
    }
    # codec_header:
    # base64 encoded 4 byte string: first 2 bytes for sample rate, 3rd for number of frames per packet (1 or 2), 4th for the frame size
    # gd4BPA==  => 0x80 0x3e 0x01 0x3c  => 16000 Hz, 1 frame per packet, 60 ms frame size
    frames_per_packet = 1
    packet_duration = 60
    codec_header = base64.b64encode(
        config["zello_sample_rate"].to_bytes(2, "little") + frames_per_packet.to_bytes(1, "big") +
        packet_duration.to_bytes(1, "big")
    ).decode()
    send["codec_header"] = codec_header
    send["packet_duration"] = packet_duration

    for attempt in range(8):
        send["seq"] = next_seq()
        try:
            pending.arm()
            conn.send_json(send)
        except Exception as ex:
            pending.disarm()
            LOG.error("send exception %s", ex)
            return None
        data = pending.wait(timeout=2.0)
        pending.disarm()
        if data is None:
            LOG.warning("timed out waiting for start_stream response")
            continue
        LOG.debug("data: %s", data)
        if "stream_id" in data:
            return int(data["stream_id"])
        if "error" in data:
            LOG.warning("error %s", data["error"])
        time.sleep(0.5)
    LOG.warning("bailing out")
    return None


def stop_stream(conn, stream_id):
    try:
        conn.send_json({"command": "stop_stream", "stream_id": stream_id})
    except Exception as ex:
        LOG.error("exception: %s", ex)


def create_encoder(config):
    # Zello stream is encoded as mono PCM.
    return opuslib.api.encoder.create_state(config["zello_sample_rate"], 1,
                                            opuslib.APPLICATION_AUDIO)


def create_decoder(sample_rate):
    return opuslib.api.decoder.create_state(sample_rate, 1)


def run_ptt_command(msg, command_list, delay):
    if isinstance(command_list, str):
        command = shlex.split(command_list)
    else:
        command = [str(part) for part in command_list]
    if not command:
        LOG.warning("Skipping empty PTT command for %s", msg)
        return
    LOG.debug("%s after %.1f seconds", " ".join(command), delay)
    time.sleep(delay)
    run_command = subprocess.run(command, shell=False)
    LOG.info("%s exited with code %d", msg, run_command.returncode)


def set_ptt_serial(config, enabled: bool):
    """Assert or release RTS for PTT. Respects ptt_rts_invert."""
    if not config.get("ptt_serial_support"):
        return
    ser = config.get("ptt_serial")
    if not ser:
        return
    try:
        # If invert is True, logic is reversed
        ser.rts = (not enabled) if config.get("ptt_rts_invert", False) else enabled
        LOG.debug("PTT (RTS) %s", "ON" if enabled else "OFF")
    except Exception as ex:
        LOG.error("Failed to set PTT (RTS): %s", ex)


def open_serial_safe(port, baud=9600):
    """Open serial without toggling RTS/DTR; immediately drive both low."""
    ser = serial.Serial(port=port, baudrate=baud, timeout=0, rtscts=False, dsrdtr=False)
    try:
        ser.setRTS(False)
        ser.setDTR(False)
    except Exception:
        pass
    return ser


def start_cor_watch(config):
    """
    Start a background CTS watcher.
    - Reuses PTT serial if ports match; otherwise opens its own (safe) handle.
    - Sets config['cor_active_event'] to an Event reflecting logical CTS (with optional inversion).
    Returns (thread, cor_own_handle_or_None).
    """
    cor_port = config.get("cor_serial_port")
    if not cor_port:
        return None, None

    # Reuse PTT handle if same port
    if config.get("ptt_serial") and cor_port == config.get("ptt_serial_port"):
        ser = config["ptt_serial"]
        own_handle = None
        LOG.info("COR will monitor CTS on existing PTT serial: %s", cor_port)
    else:
        try:
            ser = open_serial_safe(cor_port, 9600)
            own_handle = ser
            LOG.info("Opened COR serial on %s", cor_port)
        except Exception as ex:
            LOG.error("Failed to open COR serial %s: %s", cor_port, ex)
            return None, None

    debounce_s = max(0, config.get("cor_cts_debounce_ms", 30)) / 1000.0
    invert = bool(config.get("cor_cts_invert", False))
    evt = Event()
    config["cor_active_event"] = evt

    def logical(line_state_high: bool) -> bool:
        # CTS True means HIGH/asserted; apply inversion if requested
        return (not line_state_high) if invert else bool(line_state_high)

    def watcher():
        last = ser.cts
        # Initial stabilization
        if debounce_s > 0:
            time.sleep(debounce_s)
        init_active = logical(ser.cts)
        if init_active:
            evt.set()
        else:
            evt.clear()
        LOG.debug("COR initial CTS=%s -> active=%s (invert=%s)", "HIGH" if ser.cts else "LOW", evt.is_set(), invert)
        try:
            while True:
                s = ser.cts
                if s != last:
                    # Debounce: require stability
                    if debounce_s > 0:
                        end = time.time() + debounce_s
                        stable = True
                        while time.time() < end:
                            if ser.cts != s:
                                stable = False
                                break
                            time.sleep(0.005)
                        if not stable:
                            last = ser.cts
                            continue
                    last = s
                    if logical(s):
                        if not evt.is_set():
                            evt.set()
                            LOG.debug("COR: CTS ASSERT -> TX ON")
                    else:
                        if evt.is_set():
                            evt.clear()
                            LOG.debug("COR: CTS DROP -> TX OFF")
                time.sleep(0.01)
        except Exception as ex:
            LOG.error("COR watcher exception: %s", ex)
            try:
                evt.clear()
            except Exception:
                pass

    th = Thread(target=watcher, name="cor_watch", daemon=True)
    th.start()
    return th, own_handle


class IncomingAudioHandler:
    """Decodes+plays a Zello->radio stream and drives PTT. Owned by the
    reader thread, except the PTT-off release which runs on its own Timer
    thread so a slow ptt_off_delay never blocks the reader from noticing
    the next incoming stream."""

    def __init__(self, config, audio_output_stream):
        self.config = config
        self.audio_output_stream = audio_output_stream
        self.decoder = None
        self.resampler = None
        self.zello_chunk = None
        self._lock = RLock()
        self._ptt_off_timer = None

    def on_stream_start(self, start_data):
        if "codec_header" not in start_data:
            return
        packet_duration = start_data.get("packet_duration", 0)
        b64x = base64.b64decode(start_data["codec_header"])
        sample_rate = b64x[1] * 256 + b64x[0]
        frames_per_buffer = b64x[2]
        frame_duration = b64x[3]

        self.zello_chunk = (sample_rate * packet_duration) // 1000
        self.decoder = create_decoder(sample_rate)
        self.resampler = Resampler(sample_rate, self.config["audio_output_sample_rate"])
        LOG.info(
            "start of bytes stream: sample_rate: %d frames_per_buffer: %d frame_duration: %d packet_duration: %d",
            sample_rate, frames_per_buffer, frame_duration, packet_duration
        )
        self._assert_ptt()

    def on_audio_frame(self, received):
        if self.decoder is None or not received or received[0] != 1:
            return
        data = received[9:]
        try:
            audio = opuslib.api.decoder.decode(self.decoder, data, len(data), self.zello_chunk, False, 1)
        except Exception as ex:
            LOG.error("Opus decode error: %s", ex)
            return
        vol_adjust = self.config["audio_output_volume"] / max(1, self.config["audio_output_channels"])
        np_audio = repeat(frombuffer(audio, dtype=short), self.config["audio_output_channels"]) * vol_adjust
        np_audio = self.resampler.process(np_audio.astype(short))
        try:
            self.audio_output_stream.write(np_audio.tobytes())
        except Exception as ex:
            LOG.error("Playback write error: %s", ex)

    def on_stream_end(self):
        if self.decoder is None:
            return
        LOG.info("end of bytes stream")
        self.decoder = None
        self._schedule_ptt_release()

    def shutdown(self):
        with self._lock:
            if self._ptt_off_timer:
                self._ptt_off_timer.cancel()
                self._ptt_off_timer = None
        self._do_ptt_off()

    def _assert_ptt(self):
        with self._lock:
            if self._ptt_off_timer:
                # A new stream arrived before the previous PTT-off fired;
                # cancel the release instead of chattering PTT off/on.
                self._ptt_off_timer.cancel()
                self._ptt_off_timer = None
                return
        try:
            set_ptt_serial(self.config, True)
        except Exception as ex:
            LOG.error("PTT (RTS) enable failed: %s", ex)
        if self.config.get("ptt_command_support"):
            Thread(target=run_ptt_command, args=("PTT on", self.config["ptt_on_command"], 0), daemon=True).start()

    def _schedule_ptt_release(self):
        delay = self.config.get("ptt_off_delay", 2)
        with self._lock:
            self._ptt_off_timer = Timer(delay, self._do_ptt_off)
            self._ptt_off_timer.daemon = True
            self._ptt_off_timer.start()

    def _do_ptt_off(self):
        with self._lock:
            self._ptt_off_timer = None
        try:
            set_ptt_serial(self.config, False)
        except Exception as ex:
            LOG.error("PTT (RTS) disable failed: %s", ex)
        if self.config.get("ptt_command_support"):
            run_ptt_command("PTT off", self.config["ptt_off_command"], self.config.get("ptt_off_delay", 2))


def reader_thread_run(config, conn, pending, stop_event, incoming):
    """Owns the only recv() call on the websocket. Dispatches control-message
    replies (e.g. start_stream results) to whichever thread is waiting via
    `pending`, and audio/on_stream_start/on_stream_stop to `incoming`."""
    while not stop_event.is_set():
        if not conn.connected.is_set():
            if not conn.connect():
                stop_event.wait(1)
                continue
        try:
            received = conn.recv(timeout=0.5)
        except socket.timeout:
            continue
        except websocket.WebSocketTimeoutException:
            continue
        except Exception as ex:
            LOG.warning("connection lost while receiving: %s", ex)
            conn.mark_disconnected()
            incoming.on_stream_end()
            continue

        if isinstance(received, bytes):
            incoming.on_audio_frame(received)
            continue

        try:
            data = json.loads(received)
        except json.JSONDecodeError as ex:
            LOG.warning("invalid JSON frame from websocket: %s", ex)
            continue

        LOG.debug("recv: %s", data)
        command = data.get("command")
        if command == "on_stream_start":
            incoming.on_stream_start(data)
        elif command == "on_stream_stop":
            incoming.on_stream_end()
        elif command:
            pass  # other named push events (e.g. on_channel_status) are ignored
        elif pending.is_active() and ("stream_id" in data or "error" in data):
            # Only bare, command-less messages (start_stream/logon acks) can
            # ever satisfy a pending request -- on_stream_start also carries
            # a stream_id and must never be mistaken for one, or an incoming
            # transmission that races with our own start_stream gets silently
            # swallowed here instead of reaching IncomingAudioHandler.
            pending.fulfill(data)


def _queue_put_drop_oldest(q, item, warn_state):
    """Push onto a bounded queue, dropping the oldest item on overflow
    instead of blocking capture (and falling further and further behind
    real-time, which is how audio used to back up for minutes)."""
    while True:
        try:
            q.put_nowait(item)
            return
        except queue.Full:
            try:
                q.get_nowait()
            except queue.Empty:
                pass
            now = time.time()
            if now - warn_state[0] > 1.0:
                LOG.warning("TX queue overflowed, dropping oldest audio (Zello send can't keep up)")
                warn_state[0] = now


def capture_thread_run(config, stop_event, tx_queue, resampler, audio_input_stream):
    channel = config["in_channel_config"]
    source = config["audio_source"]
    warn_state = [0.0]
    framer = FrameAccumulator(int(config["zello_sample_rate"] * CHUNK_SECONDS))
    while not stop_event.is_set():
        if source == "Sound Card":
            data = record_chunk(config, audio_input_stream, resampler, channel=channel)
        elif source == "UDP":
            data = get_udp_audio(config, resampler, seconds=CHUNK_SECONDS, channel=channel)
            if len(data) == 0:
                stop_event.wait(CHUNK_SECONDS)
                continue
        else:
            return
        for frame in framer.push(data):
            _queue_put_drop_oldest(tx_queue, frame, warn_state)


def tx_thread_run(config, conn, pending, stop_event, tx_queue):
    enc = create_encoder(config)
    zello_chunk = int(config["zello_sample_rate"] * CHUNK_SECONDS)
    cor_mode = bool(config.get("cor_serial_port"))
    hang_chunks = config["vox_silence_time"] * (1 / CHUNK_SECONDS)
    packet_id = 0  # packet ID is only used in server to client - populate with zeros for client to server direction

    active = False
    stream_id = None
    quiet_samples = 0
    session_timer = 0.0

    def stop_active():
        nonlocal active, stream_id
        if active and stream_id:
            LOG.info("Done sending audio")
            stop_stream(conn, stream_id)
        active = False
        stream_id = None

    try:
        while not stop_event.is_set():
            try:
                data = tx_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            level = max(abs(data)) if len(data) else 0
            cor_active = cor_mode and bool(config.get("cor_active_event") and config["cor_active_event"].is_set())
            triggered = (cor_mode and cor_active) or (not cor_mode and level > config["audio_threshold"])

            if not active:
                if not triggered:
                    continue
                LOG.info("COR active -> TX" if cor_mode else "Audio on")
                if not conn.connected.is_set():
                    LOG.warning("Cannot establish connection")
                    stop_event.wait(1)
                    continue
                stream_id = start_stream(config, conn, pending)
                if not stream_id:
                    LOG.warning("Cannot start stream")
                    stop_event.wait(1)
                    continue
                LOG.info("sending to stream_id %d", stream_id)
                active = True
                quiet_samples = 0
                session_timer = time.time()

            if time.time() - session_timer > 30:
                LOG.info("Timer break")
                stop_stream(conn, stream_id)
                stream_id = start_stream(config, conn, pending)
                if not stream_id:
                    LOG.warning("Cannot start stream")
                    active = False
                    continue
                session_timer = time.time()

            if len(data) > 0:
                data2 = data.tobytes()
                out = opuslib.api.encoder.encode(enc, data2, zello_chunk, len(data2) * 2)
                send_data = bytearray(array([1]).astype(">u1").tobytes())
                send_data += array([stream_id]).astype(">u4").tobytes()
                send_data += array([packet_id]).astype(">u4").tobytes()
                send_data += out
                try:
                    nbytes = conn.send_binary(send_data)
                    if not nbytes:
                        LOG.warning("Binary send error")
                        active = False
                        stream_id = None
                        continue
                except Exception as ex:
                    LOG.error("Zello error %s", ex)
                    conn.mark_disconnected()
                    active = False
                    stream_id = None
                    continue

            if cor_mode:
                if not cor_active:
                    stop_active()
            else:
                if level > config["audio_threshold"]:
                    quiet_samples = 0
                else:
                    quiet_samples += 1
                    if quiet_samples >= hang_chunks:
                        stop_active()
    finally:
        stop_active()


def main():
    global udpdata, processing, udp_buffer_lock
    processing = True
    udpdata = b''
    audio_input_stream = None
    audio_output_stream = None
    p = None
    UDPSock = None
    udp_rx_thread = None

    try:
        config = get_config()
        # ---- PTT serial: make it explicit and visible in logs
        LOG.debug("PTT config: port=%r, invert=%s", config.get("ptt_serial_port"), config.get("ptt_rts_invert", False))
        config["ptt_serial_support"] = bool(config.get("ptt_serial_port"))

        # Open PTT serial (RTS control)
        if config.get("ptt_serial_support"):
            try:
                ser = serial.Serial(
                    port=config["ptt_serial_port"],
                    baudrate=9600,  # arbitrary; control lines don't need a specific rate
                    timeout=0,
                    rtscts=False,  # we control RTS manually
                    dsrdtr=False
                )
                # Store handle and ensure RTS is idle (off)
                config["ptt_serial"] = ser
                initial_rts = (not True) if config["ptt_rts_invert"] else False
                ser.rts = initial_rts
                LOG.info("Opened PTT serial on %s", config["ptt_serial_port"])
            except Exception as ex:
                LOG.error("Failed to open PTT serial %s: %s", config["ptt_serial_port"], ex)
                config["ptt_serial_support"] = False
        else:
            LOG.debug("PTT serial disabled (no ptt_serial_port set)")

        # Start COR watcher if configured
        cor_thread = None
        cor_own_handle = None
        if config.get("cor_serial_port"):
            cor_thread, cor_own_handle = start_cor_watch(config)

    except ConfigException as ex:
        LOG.critical("configuration error: %s", ex)
        sys.exit(1)

    log_level = logging.getLevelName(config["logging_level"].upper())
    LOG.setLevel(log_level)

    if config["audio_source"] == "Sound Card":
        LOG.debug("start PyAudio")
        p = pyaudio.PyAudio()
        LOG.debug("started PyAudio")
        audio_input_stream, audio_output_stream = start_audio(config, p)
    elif config["audio_source"] == "UDP":
        p = pyaudio.PyAudio()
        audio_output_stream = start_output_audio(config, p)
        # Set up a UDP server to receive audio from trunk-recorder
        UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        UDPSock.settimeout(.5)
        listen_addr = ("", config["udp_port"])
        UDPSock.bind(listen_addr)
        udp_buffer_lock = RLock()
        udp_rx_thread = Thread(target=udp_rx, args=(UDPSock, config), name="udp_rx")
        udp_rx_thread.start()
    else:
        LOG.critical("Invalid Audio Source")
        sys.exit(1)

    stop_event = Event()
    tx_queue = queue.Queue(maxsize=max(1, int(MAX_QUEUE_SECONDS / CHUNK_SECONDS)))
    capture_resampler = Resampler(config["audio_input_sample_rate"], config["zello_sample_rate"])
    conn = ZelloConnection(config)
    pending = PendingReply()
    incoming = IncomingAudioHandler(config, audio_output_stream)

    threads = [
        Thread(target=capture_thread_run, name="capture",
               args=(config, stop_event, tx_queue, capture_resampler, audio_input_stream)),
        Thread(target=tx_thread_run, name="tx",
               args=(config, conn, pending, stop_event, tx_queue)),
        Thread(target=reader_thread_run, name="reader",
               args=(config, conn, pending, stop_event, incoming)),
    ]
    for t in threads:
        t.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        LOG.info("keyboard interrupt caught")

    LOG.info("terminating")
    processing = False
    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    incoming.shutdown()
    conn.mark_disconnected()

    if config["audio_source"] == "Sound Card":
        audio_input_stream.close()
        audio_output_stream.close()
        p.terminate()
    elif config["audio_source"] == "UDP":
        if udp_rx_thread:
            udp_rx_thread.join(timeout=2)
        UDPSock.close()
        audio_output_stream.close()
        p.terminate()

    # Close COR handle only if we opened an extra one (not the shared PTT handle)
    try:
        if cor_own_handle:
            cor_own_handle.close()
    except Exception as ex:
        LOG.error("Error closing COR serial: %s", ex)

    if config.get("ptt_serial_support") and config.get("ptt_serial"):
        try:
            # ensure PTT released
            off_val = (not True) if config["ptt_rts_invert"] else False
            config["ptt_serial"].rts = off_val
            config["ptt_serial"].close()
        except Exception as ex:
            LOG.error("Error closing PTT serial: %s", ex)


if __name__ == "__main__":
    main()
