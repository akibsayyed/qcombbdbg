set target-async on
set non-stop on
set displaced-stepping off
set print pretty on

symbol-file src/qcombbdbg/qcombbdbg.elf

# Intercept REX panics
break *((int)&rex_fatal_error & ~1)
commands
  silent
  set $task_name = ((rex_task *)rex_self())->name
  printf "\n[REX Panic!]\n" 
  printf "    Task: %s\n", $task_name
  if $r2 != 0
    printf "    File: '%s'\n", $r1
    printf "    Msg:  '%s'\n", $r2
  else
    printf "    Msg:  '%s'\n", $r1
  end
end

define connect
  dont-repeat

  # Connect to proxy
  target remote localhost:$arg0

  # List REX tasks
  info threads
end

