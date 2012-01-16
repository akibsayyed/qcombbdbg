#!/usr/bin/env ruby

=begin

= File
	gdbproxy.rb

= Info
	This file is part of qcombbdbg.
	Copyright (C) 2012	Guillaume Delugré <guillaume@security-labs.org>
	All right reserved.
	
  qcombbdbg is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  qcombbdbg is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with qcombbdbg.  If not, see <http://www.gnu.org/licenses/>.

=end

$: << '..'
require 'socket'
require 'strscan'
require 'rexml/document'

require 'diagtaskclient'
  
module Commands
  ATTACH = 0
  DETACH = 1
  GET_NUM_TASKS = 2
  GET_TASK_INFO = 3
  GET_TASK_STATE = 4
  STOP_TASK = 5
  RESUME_TASK = 6
  READ_MEM = 7
  WRITE_MEM = 8
  GET_REGS = 9
  SET_REGS = 10
  INSERT_BP = 11
  REMOVE_BP = 12

  INSERT_TP = 13
  REMOVE_TP = 14
  TRACE_CLEAR = 15
  TRACE_START = 16
  TRACE_STOP = 17
  TRACE_STATUS = 18
  GET_TVAR = 19
  SET_TVAR = 20

  DEBUG_ECHO = 0x80
  DEBUG_CALL = 0x81
  DEBUG_EXCEPTION = 0x82
  DEBUG_OVERFLOW = 0x83
  DEBUG_SEND_SIGNAL = 0x84
  DEBUG_RELOC_INSN = 0x85
end

module Event
  STOP = 0
  BKPT = 1
  MEMORY_FAULT = 2
  ILLEGAL_INSTRUCTION = 3
end

module Exceptions
  UNDEF = 0
  SOFT = 1
  PREFETCH = 2
  ABORT_DATA = 3
end

module PacketType
  RESPONSE = "\x00"
  EVENT = "\x01"
end

module TaskState
  ALIVE = 0
  HALTED = 1
  DEAD = 2
  UNKNOWN = 3
end

module CpuState
  ARM = 0
  THUMB = 1
end

module Signals
  ILL = 4
  TRAP = 5
  BUS = 7
  SEGV = 11
end

module TraceStop
  NOT_RUN = 1
  USER = 2
  BUFFER_FULL = 3
  DISCONNECTED = 4
  NO_MORE_PASS = 5
  ERROR = 6
  UNKNOWN = 7
end

class Tracepoint
  attr_reader :actions

  def initialize(n, addr, pass, condition)
    @n = n
    @addr = addr
    @pass = pass
    @condition = condition
    @actions = []
  end
end

SIGMAP = Hash.new(0).update({
  Event::STOP => 0,
  Event::BKPT => Signals::TRAP,
  Event::MEMORY_FAULT => Signals::SEGV,
  Event::ILLEGAL_INSTRUCTION => Signals::ILL
})

DBG_CMD = 0x7b
DBG_BASE_ADDR = 0x1d0_0000
TARGET_XML = File.read 'target.xml'

Thread.abort_on_exception = true

class GdbProxy
  PACKET_SIZE = 0x3fff
  SUPPORTED_FEATURES = 
  [
    'QNonStop',
    'QStartNoAckMode',
    'qXfer:features:read',
    'qXfer:threads:read'
  ]

  def initialize(port, tty)
    @gdbsrv = TCPServer.new('localhost', port) 
    @diag = DiagTaskClient.new(tty, STDERR)

    @diag.wait_for_async_packets do |event|
      @events.push(event)
      process_async_pending_event
    end
  end

  def run
    loop do
      @gdb = @gdbsrv.accept
      dbg_attach
      
      @ack = true
      @first_byte = true
      @current_task = 1
      @events = []
      @event_reporting_in_progress = false
      @tracepoints = {}

      loop do
        break unless @gdb and not @gdb.eof?

        begin
          if @ack and (c = @gdb.read(1)) != "+" and not @first_byte
            fail "Missing +, got #{c.inspect}"
          end
      
          if not @first_byte or (@first_byte and c == '+')
            c = @gdb.read(1)

            if c == "\x03"
              puts "Recv = <BREAK SEQUENCE>"
              dbg_stop_task(@current_task)
              send_packet('OK')
              next
            elsif c != "$"
              fail "Missing $, got #{c.inspect}"
            end
          end
          
          @ack = false if @ack == :disable
          @first_byte = false

          data = ""
          while (c = @gdb.read(1)) != "#"
            data << c
          end

          sentsum = @gdb.read(2).hex
          csum = 0
          data.each_byte do |b|
            csum += b
            csum &= 0xff
          end

          fail "Bad checksum: got #{sentsum} instead of #{csum}" if csum != sentsum
          @gdb.print('+')

          handle_packet(data)
        rescue Exception => e
          STDERR.puts "Error: #{e.message} (#{e.backtrace[0]})"
          @gdb.close
          @gdb = nil
          dbg_detach
        end
      end
    end
  end

  private

  def dbg_send_cmd(cmd, *args)
    @diag.enter_full_sync_mode
    resp = @diag.send_raw_cmd DiagTaskClient::Command.new(DBG_CMD, [ cmd, :u8], *args)
    loop do
      case resp[0,1]
        when PacketType::RESPONSE
          @diag.leave_full_sync_mode
          if resp[1,1] == "\x00"
            return resp[2..-1]
          else
            return nil # error
          end

        when PacketType::EVENT
          @events.push(resp)
          process_async_pending_event
          resp = @diag.read_raw_response
        else
          fail "Unknown packet returned: #{resp}"
       end
    end
  end

  def dbg_attach
    dbg_send_cmd(Commands::ATTACH)
  end

  def dbg_detach
    dbg_send_cmd(Commands::DETACH)
  end

  def dbg_get_trace_status
    resp = dbg_send_cmd(Commands::TRACE_STATUS)

    if resp
      status, circular, tframes, tcreated, tsize, tfree =
        resp.unpack('C2V4')

      info = {
        :disconn => 0,
        :trunning => (status == 0) ? 1 : 0,
        :circular => circular,
        :tframes => tframes,
        :tcreated => tcreated,
        :tsize => tsize,
        :tfree => tfree
      }

      if status != 0
        case status
          when TraceStop::NOT_RUN
            info[:tnotrun] = 0
          when TraceStop::USER
            info[:tstop] = 0
          when TraceStop::BUFFER_FULL
            info[:tfull] = 0
          when TraceStop::DISCONNECTED
            info[:tdisconnected] = 0
        else
          info[:tunknown] = 0
        end
      end

      info
    end
  end

  def dbg_get_num_tasks
    resp = dbg_send_cmd(Commands::GET_NUM_TASKS)
    resp.unpack('V')[0]
  end

  def dbg_stop_task(tid)
    dbg_send_cmd(Commands::STOP_TASK, [ tid, :u32 ])
  end

  def dbg_continue_task(tid)
    dbg_send_cmd(Commands::RESUME_TASK, [ tid, :u32 ])
  end

  def dbg_get_task_desc(tid)
    resp = dbg_send_cmd(Commands::GET_TASK_INFO, [ tid, :u32])
  
    wait, active, name = resp.unpack('V2A*')
    {
      :wait_signals => wait,
      :active_signals => active,
      :name => name
    }
        
    "#{name.ljust(13)} [wait: 0x#{wait.to_s(16).rjust(8,'0')}; active: 0x#{active.to_s(16).rjust(8,'0')}]"
  end

  def build_xml_thread_list
    @ntasks ||= dbg_get_num_tasks
    thr_xml_template = '<?xml version="1.0"?><threads></threads>'
    thr_xml = REXML::Document.new(thr_xml_template)

    (1..@ntasks).each do |tid|
      thr_entry = REXML::Element.new('thread')
      thr_entry.add_attribute('id', tid.to_s(16))
      thr_entry.text = dbg_get_task_desc(tid)

      thr_xml.root.add_element(thr_entry)
    end

    thr_xml.to_s
  end

  def dbg_get_task_state(tid)
    resp = dbg_send_cmd(Commands::GET_TASK_STATE, [ tid, :u32])

    resp.unpack('V')[0]
  end

  def dbg_insert_breakpoint(addr, kind)
    dbg_send_cmd(Commands::INSERT_BP, [ addr, :u32 ], [ kind, :u8 ])
  end

  def dbg_remove_breakpoint(addr, kind)
    dbg_send_cmd(Commands::REMOVE_BP, [ addr, :u32 ])
  end

  def dbg_read_memory(addr, size)
    dbg_send_cmd(
      Commands::READ_MEM,
      [ addr, :u32 ],
      [ size, :u32 ]
    )
  end

  def dbg_write_memory(addr, data)
    dbg_send_cmd(
      Commands::WRITE_MEM,
      [ addr, :u32 ],
      [ data, :blob ]
    )
  end

  def dbg_get_registers(tid)
    resp = dbg_send_cmd(Commands::GET_REGS, [ tid, :u32])
    if resp
      cpsr,
      r0, r1, r2, r3,
      r4, r5, r6, r7,
      r8, r9, r10, r11,
      r12, lr, pc, sp = resp.unpack('V17')

      [ 
        r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, 
        nil, nil, nil, nil, nil, nil, nil, nil, nil,
        cpsr
      ]
    end
  end

  def dbg_set_registers(tid, regs)
    r  = [ regs[25] ].pack('V')  # cspr
    r += regs[0, 13].pack('V13')   # r0-r12
    r += [ regs[14] ].pack('V') # lr
    r += [ regs[15] ].pack('V') # pc
    r += [ regs[13] ].pack('V') # sp

    dbg_send_cmd(Commands::SET_REGS, [ tid, :u32 ], [ r, :blob ])
  end

  def process_async_pending_event
    unless @event_reporting_in_progress
      event = @events.first

      type, tid, cause, cpsr,
      r0, r1, r2, r3,
      r4, r5, r6, r7,
      r8, r9, r10, r11,
      r12, lr, pc, sp = event.unpack('CV2V17')

      regs = [ r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc ]

      stop = "T#{SIGMAP[cause].chr.unpack('H2')[0]}"
      stop += (0..15).to_a.map{|r| r.chr.unpack('H2')[0] + ':' + [regs[r]].pack('V').unpack('N')[0].to_s(16).rjust(8,'0')}.push("19:#{[cpsr].pack('V').unpack('N')[0].to_s(16).rjust(8,'0')}").join(';')
      stop += ";thread:#{tid.to_s(16)};"

      send_notification("Stop:#{stop}")
      @event_reporting_in_progress = true
    end
  end

  def process_sync_pending_event
    event = @events.first

    type, tid, cause, cpsr,
    r0, r1, r2, r3,
    r4, r5, r6, r7,
    r8, r9, r10, r11,
    r12, lr, pc, sp = event.unpack('CV2V17')

    regs = [ r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc ]

    stop = "T#{SIGMAP[cause].chr.unpack('H2')[0]}"
    stop += (0..15).to_a.map{|r| r.chr.unpack('H2')[0] + ':' + [regs[r]].pack('V').unpack('N')[0].to_s(16).rjust(8,'0')}.push("19:#{[cpsr].pack('V').unpack('N')[0].to_s(16).rjust(8,'0')}").join(';')
    stop += ";thread:#{tid.to_s(16)};"

    send_packet(stop)
  end

  def handle_packet(data)
    puts "Recv = #{data}"

    unescape_packet_data(data)
    
    case data
      when /^!/
        send_packet('OK')

      when /^D/
        dbg_detach
        send_packet('OK')

      when /^qSupported(:?(.*))/
        report_supported(*$2.split(';'))

      when /^qXfer:features:read:target\.xml:(.*),(.*)/
        offset, length = $1.hex, $2.hex
        code =
          if offset + length < TARGET_XML.length
            'm'
          else
            'l'
          end

        send_packet("#{code}#{TARGET_XML[offset, length]}")

      when /^qXfer:threads:read::(.*),(.*)/
        offset, length = $1.hex, $2.hex
        
        @xml_thread_list = build_xml_thread_list if offset == 0
        code = 
          if offset + length < @xml_thread_list.length
            'm'
          else
            'l'
          end

        send_packet("#{code}#{@xml_thread_list[offset, length]}")

      when /^QNonStop:(\d)/
        fail "Non-stop mode must be enabled" if $1.to_i == 0
        send_packet('OK')

      when /^QStartNoAckMode/
        @ack = :disable
        send_packet('OK')

      when /^qfThreadInfo/
        @ntasks ||= dbg_get_num_tasks
        send_packet("m#{(1..@ntasks).to_a.map{|t| t.to_s(16)}.join(',')}")

      when /^qsThreadInfo/
        send_packet('l')

      when /^qThreadExtraInfo,(.*)/
        id = $1.hex
        
        desc = dbg_get_task_desc(id) 
        send_packet(desc.unpack('H*')[0])

      when /^qAttached/
        send_packet('1')

      when /^qC/
        send_packet("QC#{@current_task.to_s(16)}")

      when /^qOffsets/
        send_packet("TextSeg=#{DBG_BASE_ADDR.to_s 16}")

      when /^qSymbol::/
        send_packet('OK')

      when /^QTinit/
        dbg_send_cmd(Commands::TRACE_CLEAR)
        send_packet('OK')

      when /^QTDV:(.+):(.+)/
        n = $1.hex
        value = $2.hex
        dbg_send_cmd(Commands::SET_TVAR, [n, :u16], [value, :u32])
        send_packet('OK')

      when /^qTV:(.+)/
        n = $1.hex
        if resp = dbg_send_cmd(Commands::GET_TVAR, [n, :u16])
          send_packet("V#{resp.unpack('V')[0].to_s 16}") 
        else
          send_packet('U')
        end

      when /^qTStatus/
        info = dbg_get_trace_status()
        
        running = info[:trunning]
        status = info.delete_if{|k| k == :trunning}.to_a.map{ |o,v| "#{o}:#{v.to_s 16}"}.join(';')
        send_packet("T#{running};#{status}")

      when /^qTfV/, /^qTfP/
        send_packet 'l' # TODO

      when /QTDP:([^-]+):(.+):(.+):(.+):(.+)(:X(.+),(.+))?-$/
        n = $1.hex
        addr = $2.hex
        pass = $5.hex
        unless $6.empty?
          condition = $8.hex
        end

        @tracepoints[n] = Tracepoint.new(n, addr, pass, condition)
        send_packet('OK')

      when /QTDP:-(.+):(.+):(.+)-?$/
        n = $1.hex
        actions = StringScanner.new($3)
        until actions.eos?
          case actions.getch
            when 'R'
              mask = actions.scan /[0-9a-fA-F]+/
              @tracepoints[n].actions << [ :R, mask ]
            
            #when 'M'
            #  actions.scan /[0-9a-fA-F]+,[0-9a-fA-F]+,[0-9a-fA-F]+/

            when 'X'
              actions.scan /[0-9a-fA-F]+,[0-9a-fA-F]+/
              code = [ actions[1] ].pack('H*')
              @tracepoints[n].actions << [ :X, code ]

            else
              fail 'Bad QTDP packet'
          end
        end

        send_packet('OK')

      when /^vCont\?/
        send_packet('vCont;t;c;s')

      when /^vCont;([tc])(:.*)?/
        id = $2[1..-1].hex
        #@current_task = id

        case $1
          when 't'
            dbg_stop_task(id)

          when 'c'
            dbg_continue_task(id) 

        end
        send_packet('OK')

      when /^vStopped/
        @events.shift
        if @events.empty?
          @event_reporting_in_progress = false
          send_packet('OK')
        else
          process_sync_pending_event
        end

      when /^\?/
        if @events.empty?
          @event_reporting_in_progress = false
          send_packet('OK')
        else
          @event_reporting_in_progress = true
          process_sync_pending_event
        end

      when /^H(.)(.*)/
        id = $2.hex
        id = 1 if id == 0
        @current_task = id
        send_packet('OK')

      when /^T(.*)/
        #id = $1.hex
        #state = dbg_get_task_state(id)
        #if state != TaskState::DEAD
          send_packet('OK')
        #else
        #  send_packet('E00')
        #end

      when /^m(.+),(.+)/
        data = dbg_read_memory($1.hex, $2.hex)
        if data
          send_packet(data.unpack('H*')[0])
        else
          send_packet('E00')
        end

      when /^M(.+),(.+):(.*)/
        addr = $1.hex
        size = $2.hex

        if size > 0
          data = [ $3 ].pack 'H*'
          if dbg_write_memory(addr, data)
            send_packet('OK')
          else
            send_packet('E00')
          end
        else
          send_packet('OK')
        end

      when /^X(.+),(.+):(.*)/
        addr = $1.hex
        size = $2.hex

        if size > 0
          if dbg_write_memory(addr, $3)
            send_packet('OK')
          else
            send_packet('E00')
          end
        else
          send_packet('OK')
        end

      when /^g/
        regs = dbg_get_registers(@current_task)
        if regs
          data = (0..15).to_a.map{|r| 
            [regs[r]].pack('V').unpack('N')[0].to_s(16).rjust(8,'0')
          }.join
          send_packet(data)
        else
          send_packet('E00')
        end

      when /^p(.*)/
        r = $1.hex
        regs = dbg_get_registers(@current_task)
        if regs and regs[r]
          value = [regs[r]].pack('V').unpack('N')[0].to_s(16).rjust(8,'0')
          send_packet(value)
        else
          send_packet('E00')
        end

      when /^P(.+)=(.+)/
        r = $1.hex
        value =  [ $2 ].pack('H*').unpack('V')[0]

        regs = dbg_get_registers(@current_task)
        regs[r] = value
        dbg_set_registers(@current_task, regs)
        send_packet('OK')

      when /^c(.*)/ 
        unless $1.empty?
          addr = $1.hex
          regs = dbg_get_registers(@current_task)
          regs[15] = addr
          dbg_set_registers(@current_task, regs)
        end
        dbg_continue_task(@current_task)
        #send_packet('OK')

      when /^C(.+)(;?(.+))/
        unless $3.empty?
          addr = $3.hex
          regs = dbg_get_registers(@current_task)
          regs[15] = addr
          dbg_set_registers(@current_task, regs)
        end
        dbg_continue_task(@current_task)
        #send_packet('OK')
        
      when /^([zZ])(.),(.*),(.*)/
        addr = $3.hex
        kind = $4.hex == 4 ? CpuState::ARM : CpuState::THUMB
        
        ret= case $2.hex
          when 0
            if $1 == 'Z'
              dbg_insert_breakpoint(addr, kind)
            else
              dbg_remove_breakpoint(addr, kind)
            end
        else
          raise NotImplementedError
        end
        
        if ret
          send_packet('OK')
        else
          send_packet('E00')
        end
      
      # Custom command, triggers exception in remote task (debug purpose only).
      when /^xCustom:Exception:(.*):(.*)/
        dbg_send_cmd(Commands::DEBUG_EXCEPTION,
          [ $1.hex, :u32 ], [ $2.hex, :u32 ]
        )
        send_packet('OK')
         
      # Custom command, triggers exception in remote task (debug purpose only).
      when /^xCustom:Overflow:(.*):(.*)/
        dbg_send_cmd(Commands::DEBUG_OVERFLOW,
          [ $1.hex, :u32 ], [ $2, :blob ]
        )
        send_packet('OK')

      when /^xCustom:Reloc:(.*):(.*)/
        src = $1.hex
        dst = $2.hex
        dbg_send_cmd(Commands::DEBUG_RELOC_INSN,
          [ src, :u32 ],
          [ dst, :u32 ]
        )
        send_packet('OK')

    else
      fail data #XXX: remove
      send_packet('')
    end
  end

  def report_supported(*features)
    supported = [ "PacketSize=#{PACKET_SIZE.to_s(16)}" ]

    SUPPORTED_FEATURES.each do |feature|
      supported << feature + '+'
    end

    send_packet(supported.join(';'))
  end

  def send_notification(data)
    escape_packet_data(data)

    csum = 0
    data.each_byte do |b|
      csum += b
      csum &= 0xff
    end

    packet = "%#{data}##{csum.to_s(16).rjust(2, '0')}"
    puts "Notification = #{packet}"
    @gdb.write(packet)
  end

  def send_packet(data)
    escape_packet_data(data)

    csum = 0
    data.each_byte do |b|
      csum += b
      csum &= 0xff
    end

    packet = "$#{data}##{csum.to_s(16).rjust(2, '0')}"
    puts "Send = #{packet}"
    @gdb.write(packet)
  end

  def escape_packet_data(data)
    data.gsub! "\x7d", "\x7d\x5d" # escape
    data.gsub! "\x23", "\x7d\x03" # '#'
    data.gsub! "\x24", "\x7d\x04" # '$'
    data.gsub! "\x2a", "\x7d\x0a" # '*'
   
    data
  end

  def unescape_packet_data(data)  
    data.gsub! "\x7d\x03", "\x23" # '#'
    data.gsub! "\x7d\x04", "\x24" # '$'
    data.gsub! "\x7d\x0a", "\x2a" # '*'

    data.gsub! "\x7d\x5d", "\x7d" # escape

    data
  end
end

if $0 == __FILE__
  begin
    PORT = ARGV.find{|arg| arg =~ /tcp:/i}.split(':')[1].to_i
    SERIAL = ARGV.find{|arg| arg =~ /tty:/i}.split(':')[1]

  rescue
    abort "Usage: #{$0} tcp:<PORT> tty:<FILE>"
  end

  GdbProxy.new(PORT, SERIAL).run
end
