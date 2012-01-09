set target-async on
set non-stop on
set displaced-stepping off
set print pretty on

symbol-file src/qcombbdbg/qcombbdbg.elf

define connect
  dont-repeat

  target remote localhost:$arg0
  info threads
end

