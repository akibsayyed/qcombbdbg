NAME
  
  qcombbdbg

DESCRIPTION

  Debugger for the Qualcomm baseband chip MSM6280.
  
DEPENDENCIES

  GNU ARM compilation toolchain.
  Cross-compiled GDB for ARM.
  Ruby interpreter.

DIRECTORIES

  src/preloader:              Simple stager payload to speed up the debugger injection.
  src/qcombbdbg:              Debugger sources.
  scripts/tools/dbgupload.rb: Uploads the debugger into volatile memory.
  scripts/tools/gdbproxy.rb:  Proxy to interface GDB with the live debugger.

SUPPORTED DEVICES
  
  Option Icon 225, firmware revision 2.5.13
  Option Icon 225, firmware revision 2.5.21
  Option Icon 225, firmware revision 2.5.23

USAGE

  1) Compile the preloader.bin and qcombbdbg.bin
  2) Plug the USB stick, 3 emulated serial ports should appear (under Linux, requires the hso module)
  3) Go to scripts/tools and run `ruby dbgupload.rb /dev/ttyHS2` 
  4) On success, run `ruby gdbproxy.rb tcp:1234 tty:/dev/ttyHS2`
  5) Fire GDB, and load the .gdbinit file provided in the root folder
  6) Type `connect 1234`, GDB will connect to the proxy and will import the list of threads

RANDOM NOTES

  This is still very experimental.
  
  REX creates a fake idle task named 'REX Idle Task' (Task #1).  This task is
  actually never scheduled, so you cannot break it, nor step into it. The real
  idle task is called 'SLEEP'. At startup, GDB will automatically attach to a
  thread and stop it. The debugger forces GDB to attach to the fake idle task,
  so the system will still be fully running.

  In non-stop mode, GDB will execute commands in the current thread context.
  If you want to change the current thread, use the command `thread <num>`.
  The first thing you might want to do is to interrupt the watchdog task.

  For example:

  (gdb) thread find DOG
  Thread 68 has extra info 'DOG           [wait: 0x00006800; active: 0x00000000]'
  
  (gdb) thread apply 68 interrupt
  Thread 68 (Thread 68):
  [Thread 68] #68 stopped.

  Displaced stepping is disabled for the moment (as of GDB 7.3.1, Thumb is not
  supported). Consequently, do not try to single-step or put breakpoints into
  heavily used system functions (like memcpy, rex_wait, rex_set_signals, and
  so on). If the DIAG task or the USB task encounters an exception, the
  debugger is dead.

TODO

  Tracepoints support.
  Watchpoints support.

CONTACT

  Guillaume Delugre <guillaume (at) security-labs.org>

