from __future__ import print_function
import frida
from frida_tools.application import Reactor
import threading
import time
from datetime import datetime

app_package_name = "com.tencent.mm"
hook_open_script = """
Interceptor.attach(Module.findExportByName(null, 'open'), {
  onEnter: function (args) {
    send({
      type: 'open',
      path: Memory.readUtf8String(args[0])
    });
  }
});
"""


class Application(object):
    main_hook_scripts = [
        open("./dump_keylog_main.js", 'r', encoding='utf-8').read(),
    ]
    push_hook_scripts = [
        open("./hook_libwechatnetwork.js", 'r', encoding='utf-8').read(),
    ]
    mute_main_output = False
    main_pid = 0

    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda _:
            self._stop_requested.wait())

        self._device = frida.get_usb_device(timeout=5)
        self._pid_names = {}

        print("✔ enable_spawn_gating()")
        self._device.enable_spawn_gating()
        self._sessions = set()

        self._device.on("spawn-added", lambda child:
            self._reactor.schedule(
                lambda: self._on_delivered(child)))

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        pid = self._device.spawn(app_package_name)
        self.main_pid = pid
        print("✔ spawn({})".format(app_package_name))
        self._instrument_main(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument_main(self, pid):
        print("✔ attach(pid={})".format(pid))
        session = self._device.attach(pid)
        session.on("detached", lambda reason:
            self._reactor.schedule(lambda:
                self._on_detached(pid, session, reason)))
        print("✔ create_script()")
        script = session.create_script("\n".join(self.main_hook_scripts))
        script.on("message", lambda message, data:
            self._reactor.schedule(
                lambda: self._on_message(pid, message)))
        print("✔ load()")
        script.load()

        print("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _instrument(self, process):
        if process.identifier.removeprefix(app_package_name) == ':push':
            print("✔ :push process attach(pid={})".format(process.pid))
            session = self._device.attach(process.pid)
            session.on("detached", lambda reason:
                self._reactor.schedule(lambda:
                    self._on_detached(process.pid, session, reason)))
            print("✔ create_script() 1")
            script1 = session.create_script("\n".join(self.push_hook_scripts))
            script1.on("message", lambda message, data:
                self._reactor.schedule(
                    lambda: self._on_message(process.pid, message)))
            print("✔ load()")
            script1.load()

            self._device.resume(process.pid)
            self._sessions.add(session)
            #time.sleep(1)
            #print("✔ create_script() 2")
            #script2 = session.create_script("\n".join(self.push2_hook_scripts))
            #script2.on("message", lambda message, data:
            #    self._reactor.schedule(
            #        lambda: self._on_message(process.pid, message)))
            #print("✔ resume(pid={})".format(process.pid))
            #print("✔ load() script 2")
            #script2.load()
        else:
            print("  Ignoring process "+process.identifier)

    def _on_delivered(self, child):
        print("⚡ spawn-added: {}".format(child))
        if child.identifier.startswith(app_package_name):
            self.mute_main_output = True
            self._instrument(child)

    def _on_detached(self, pid, session, reason):
        print("⚡ detached: pid={}, reason='{}'"
            .format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        if not ( pid == self.main_pid and self.mute_main_output ):
            if "payload" in message:
                payload: str = message.get("payload", "")
                payload = "\n    " + payload.replace("\n", "\n    ")
                print("⚡ {} message: pid={}, payload={}"
                    .format(datetime.now(), pid, payload))
            else:#might be a error message
                print("⚡ error: "+str(message))


app = Application()
app.run()

