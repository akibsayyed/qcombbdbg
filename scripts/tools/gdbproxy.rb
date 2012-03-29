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

  TRACE_CLEAR = 13
  TRACE_START = 14
  TRACE_STOP = 15
  TRACE_STATUS = 16
  GET_TVAR = 17
  SET_TVAR = 18
  INSERT_TP = 19
  REMOVE_TP = 20
  ENABLE_TP = 21
  DISABLE_TP = 22
  GET_TP_STATUS = 23
  SET_TP_CONDITION = 24
  ADD_TP_ACTION = 25
  GET_TRACE_FRAME = 26

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
  RESET = 4
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
  ABRT = 6
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
  module Actions
    COLLECT_REGS = 0
    COLLECT_MEM = 1
    EXEC_GDB = 2
  end

  attr_reader :addr, :pass, :condition, :actions, :src
  attr_accessor :enabled

  def initialize(addr, pass, condition = nil)
    @addr = addr
    @pass = pass
    @condition = condition
    @actions = []
    @src = []
    @enabled = true
  end
end

class TraceBuffer
  attr_reader :frames
  
  class Frame
    attr_reader :tp_num, :entries
    def initialize(tp_num)
      @tp_num = tp_num
      @entries = []
    end

    def dump
      data = ''
      @entries.each do |entry|
        data << entry.dump
      end

      [ @tp_num ].pack('S') + [ data.size ].pack('L') + data
    end

    def get_registers
      @entries.find { |entry| entry.is_a? Registers }
    end

    def read_memory(addr, size)
      requested_range = (addr...addr+size)
      mem_entries = @entries.find_all { |entry| entry.is_a?(Memory) }
      
      mem_entries.each do |mem|
        if mem.range === addr
          return mem.data[addr - mem.address, size]
        end
      end

      nil
    end
  end

  class Registers < Array
    def dump
      self.compact.map{|r| [r].pack('V')}.join
    end
  end

  class Memory
    attr_reader :address, :data
    def initialize(address, data)
      @address = address
      @data = data
    end

    def size
      @data.size
    end

    def range
      @address...(@address + @data.size)
    end

    def dump
      [ @address ].pack('Q') + [ @data.size ].pack('S') + @data
    end
  end

  class Variable
    attr_reader :n, :value
    def initialize(n, value)
      @n = n
      @value = value
    end

    def dump
      [ @n ].pack('L') + [ @value ].pack('Q')
    end
  end

  def initialize
    @frames = []
  end

  def clear
    @frames.clear
  end

  def dump
    buffer = ''
    @frames.each do |frame|
      buffer << frame.dump
    end

    buffer
  end

  def add_frame(tp_num, framebin)
    frame = Frame.new(tp_num)

    until framebin.empty?
      entry =
        case type = framebin.slice!(0,1)
          when 'R'
            cpsr,
            r0, r1, r2, r3,
            r4, r5, r6, r7,
            r8, r9, r10, r11,
            r12, lr, pc, sp = framebin.slice!(0, 17*4).unpack('V17')
            Registers.new([ 
              r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, 
              nil, nil, nil, nil, nil, nil, nil, nil, nil,
              cpsr
            ])

          when 'M'
            addr = framebin.slice!(0,4).unpack('V')[0]
            size = framebin.slice!(0,2).unpack('v')[0]
            data = framebin.slice!(0, size)
            Memory.new(addr, data)
          
          when 'V'
            id = framebin.slice!(0,2).unpack('v')[0]
            value = framebin.slice!(0,4).unpack('V')[0]
            Variable.new(id, value)
        end
      frame.entries << entry
    end

    @frames << frame
  end
end

SIGMAP = Hash.new(0).update({
  Event::STOP => 0,
  Event::BKPT => Signals::TRAP,
  Event::MEMORY_FAULT => Signals::SEGV,
  Event::ILLEGAL_INSTRUCTION => Signals::ILL,
  Event::RESET => Signals::ABRT
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
    'qXfer:threads:read',
    'EnableDisableTracepoints'
  ]

  def initialize(port, tty)
    @gdbsrv = TCPServer.new('localhost', port) 
    #out = File.open('gdbproxy.log', 'w')
    #@diag = DiagTaskClient.new(tty, out)
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
      @tracebuffer = TraceBuffer.new
      @current_frame = nil

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

  def close
    dbg_detach
    @gdb.close if @gdb
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
    @tracepoints.clear
    @tracebuffer.clear
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
          when TraceStop::NO_MORE_PASS
            info[:tpasscount] = 0
          when TraceStop::ERROR
            info[:terror] = 0
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

  def dbg_insert_tracepoint(addr, kind, pass)
    dbg_send_cmd(Commands::INSERT_TP, [ addr, :u32 ], [ kind, :u8 ], [ pass, :u32 ])
  end

  def dbg_add_tracepoint_action(addr, type, *args)
    dbg_send_cmd(Commands::ADD_TP_ACTION, [ addr, :u32 ], [ type, :u8 ], *args)
  end

  def dbg_enable_tracepoint(addr)
    dbg_send_cmd(Commands::ENABLE_TP, [ addr, :u32 ])
  end

  def dbg_disable_tracepoint(addr)
    dbg_send_cmd(Commands::DISABLE_TP, [ addr, :u32 ])
  end

  def dbg_get_tracepoint_status(addr)
    resp = dbg_send_cmd(Commands::GET_TP_STATUS, [ addr, :u32 ])
    if resp
      enabled, hits, usage = resp.unpack('CVV')
      return { :enabled => enabled, :hits => hits, :usage => usage }
    end
  end

  def dbg_get_tracebuffer_frame(n)
    dbg_send_cmd(Commands::GET_TRACE_FRAME, [ n, :u32 ])
  end

  def dbg_download_tracebuffer
    n = 0
    while (frame = dbg_get_tracebuffer_frame(n))
      tp_addr = frame.slice!(0,4).unpack('V')[0]
      tp_id = -1
      @tracepoints.each_pair do |id, tp|
        if tp.addr == tp_addr
          tp_id = id
          break
        end
      end
      @tracebuffer.add_frame(tp_id, frame)
      n = n + 1
    end
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

      when /^qTMinFTPILen/
        send_packet('') # Fast tracepoints not supported

      when /^QTinit/
        dbg_send_cmd(Commands::TRACE_CLEAR)
        send_packet('OK')

      when /^QTEnable:(.+):(.+)/
        n = $1.hex
        addr = $2.hex
        if @tracepoints.include?(n) and @tracepoints[n].addr == addr
          dbg_enable_tracepoint(addr)
          send_packet('OK')
        else
          send_packet('E00')
        end

      when /^QTDisable:(.+):(.+)/
        n = $1.hex
        addr = $2.hex
        if @tracepoints.include?(n) and @tracepoints[n].addr == addr
          dbg_disable_tracepoint(addr)
          send_packet('OK')
        else
          send_packet('E00')
        end

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

      when /^qTP:(.+):(.+)/
        n = $1.hex
        addr = $2.hex
        tpstatus = dbg_get_tracepoint_status(addr)
        if tpstatus
          send_packet("V#{tpstatus[:hits].to_s(16)}:#{tpstatus[:usage].to_s(16)}")
        else
          send_packet('E00')
        end

      when /^qTStatus/
        info = dbg_get_trace_status()
        
        running = info[:trunning]
        status = info.delete_if{|k| k == :trunning}.to_a.map{ |o,v| "#{o}:#{v.to_s 16}"}.join(';')
        send_packet("T#{running};#{status}")

      when /^QTStart/
        @tracepoints.each_pair do |id, tp|
          dbg_insert_tracepoint(tp.addr, CpuState::THUMB, tp.pass)
          tp.actions.each do |action|
            dbg_add_tracepoint_action(tp.addr, action[0], *action[1..-1])
          end
        end
        dbg_send_cmd(Commands::TRACE_START)
        send_packet('OK')

      when /^QTStop/
        dbg_send_cmd(Commands::TRACE_STOP)
        dbg_download_tracebuffer
        send_packet('OK')

      when /^QTFrame:(.+)/
        n = $1.hex 
        @current_frame = @tracebuffer.frames[n] 
        if @current_frame
          send_packet("F#{n.to_s 16}T#{@current_frame.tp_num}")
        else
          send_packet('F-1')
        end

      when /^qTfV/, /^qTfP/, /^qTsV/, /^qTsP/
        send_packet 'l' # TODO

      when /QTDP:([^-]+):(.+):(E|D):(.+):(.+)(:X(.+),(.+))?-?$/
        n = $1.hex
        addr = $2.hex
        step = $4.hex
        pass = $5.hex
        condition = $8.hex if $6

        fail "Stepping tracepoints are not supported" if step != 0

        @tracepoints[n] = Tracepoint.new(addr, pass, condition)
        send_packet('OK')

      when /QTDP:-(.+):(.+):([^-]+)-?$/
        n = $1.hex
        actions = StringScanner.new($3)
        until actions.eos?
          case type = actions.getch
            when 'R'
              mask = actions.scan /[0-9a-fA-F]+/
              @tracepoints[n].actions << [ Tracepoint::Actions::COLLECT_REGS ]
            
            #when 'M'
            #  actions.scan /[0-9a-fA-F]+,[0-9a-fA-F]+,[0-9a-fA-F]+/

            when 'X'
              actions.scan /([0-9a-fA-F]+),([0-9a-fA-F]+)/
              code = [ actions[2] ].pack('H*')
              @tracepoints[n].actions << [ Tracepoint::Actions::EXEC_GDB , [code, :blob] ]

            else
              fail "Bad QTDP packet : #{type}"
          end
        end

        send_packet('OK')

      when /^QTBuffer:circular:(.+)/
        circular = $1.hex
        send_packet('OK') # TODO

      when /^qTBuffer:(.+),(.+)/
        offset = $1.hex
        len = $2.hex

        buffer = @tracebuffer.dump[offset, len]
        if buffer
          send_packet(buffer.unpack('H*')[0])
        else
          send_packet('l')
        end

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
        if @current_frame
          data = @current_frame.read_memory($1.hex, $2.hex)
        else
          data = dbg_read_memory($1.hex, $2.hex)
        end

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
        if @current_frame #and @current_frame.entries.find{|entry| entry.is_a? TraceBuffer::Registers}
          regs = @current_frame.get_registers
        else
          regs = dbg_get_registers(@current_task)
        end

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
        if @current_frame
          regs = @current_frame.get_registers
        else
          regs = dbg_get_registers(@current_task)
        end

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

      when /^xCustom:Trace:(.*):(.*)/
        addr = $1.hex
        pass = $2.hex
        kind = CpuState::THUMB
        dbg_insert_tracepoint(addr, kind, pass)
        dbg_enable_tracepoint(addr)
        send_packet('OK')

      when /^xCustom:InfoTP:(.*)/
        addr = $1.hex
        tpstatus = dbg_get_tracepoint_status(addr)
        send_packet("V#{tpstatus[:hits].to_s(16)}:#{tpstatus[:usage].to_s(16)}")

      when /^xCustom:Frame:(.*)/
        n = $1.hex
        frame = dbg_get_tracebuffer_frame(n)
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

  begin
    proxy = GdbProxy.new(PORT, SERIAL)
    proxy.run
  ensure
    proxy.close
  end
end
