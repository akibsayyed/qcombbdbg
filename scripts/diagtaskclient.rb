=begin

= File
	diagtaskclient.rb

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

require 'fcntl'
require 'hexdump'

module CRC
  
  CRC_CCITT_TABLE =
  [
          0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
          0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
          0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
          0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
          0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
          0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
          0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
          0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
          0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
          0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
          0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
          0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
          0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
          0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
          0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
          0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
          0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
          0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
          0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
          0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
          0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
          0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
          0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
          0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
          0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
          0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
          0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
          0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
          0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
          0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
          0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
          0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
  ]

  def self.compute(data)
    crc = 0xffff

    data.each_byte do |byte|
      crc = (crc >> 8) ^ CRC_CCITT_TABLE[(crc ^ byte) & 0xff]
    end

    crc ^ 0xffff
  end
end

class DiagTaskClientError < Exception; end
class InvalidDiagPacketError < Exception; end

class DiagTaskClient
  AT_EOL = "\r"
  DIAG_EOL = "~"
  READ_MAX_RETRY = 50

  module Modes
    OFFLINE_ANALOG = 0
    OFFLINE_DIGITAL = 1
    RESET = 2
    OFFLINE_FACTORY_TEST = 3
    ONLINE = 4
  end

  module MessageLevel
    LOW = 0
    MED = 1
    HIGH = 2
    ERROR = 3
    FATAL = 4
    NONE = 0xff
  end

  class Command
    module Types
      # Diag task commands
      GET_VERSION = 0
      GET_SERIAL_NUMBER = 1
      READ_VOLATILE_B = 2
      READ_VOLATILE_W = 3
      READ_VOLATILE_D = 4
      WRITE_VOLATILE_B = 5
      WRITE_VOLATILE_W = 6
      WRITE_VOLATILE_D = 7
      GET_STATUS = 12
      LOG_REQUEST = 16
      READ_NON_VOLATILE = 17
      GET_DIAG_VERSION = 28
      TIMESTAMP = 29
      GET_MESSAGE = 31
      CHANGE_MODE = 41
      SWITCH_TO_DL_MODE = 58
      EXTENDED_BUILD_ID = 124

      # Downloader mode commands
      DL_EXEC = 5
      DL_WRITE = 15

      # Preloader commands
      PL_ECHO = 9
    end

    def initialize(type, *params)
      @type = type 
      @params = params
    end

    def to_s
      data = ''
      @params.each do |p, type|
        data << [ p ].pack(
          case type
            when :u32 then "V"
            when :u32be then "N"
            when :u16 then "v"
            when :u16be then "n"
            when :u8 then "C"
            when :blob then "a*"
          end
        )
      end

      
      packet = @type.chr + data
      packet << [ CRC.compute(packet) ].pack("v")

      packet.gsub!("\x7d", "\x7d\x5d")
      packet.gsub!("\x7e", "\x7d\x5e")

      packet + DIAG_EOL
    end

    class GetVersion < Command
      def initialize
        super(Types::GET_VERSION)
      end 
    end

    class GetSerialNumber < Command
      def initialize
        super(Types::GET_SERIAL_NUMBER)
      end
    end

    class ReadVolatile8 < Command
      def initialize(address, size)
        super(Types::READ_VOLATILE_B, [ address, :u32 ], [ size, :u16 ])
      end
    end

    class ReadVolatile16 < Command
      def initialize(address, size)
        super(Types::READ_VOLATILE_W, [ address, :u32 ], [ size, :u16 ])
      end
    end

    class ReadVolatile32 < Command
      def initialize(address, size)
        super(Types::READ_VOLATILE_D, [ address, :u32 ], [ size, :u16 ])
      end
    end

    class WriteVolatile8 < Command
      def initialize(address, data)
        super(Types::WRITE_VOLATILE_B, [ address, :u32 ], [ data.size, :u8 ], [ data.ljust(4,"\x00"), :blob ])
      end
    end

    class WriteVolatile16 < Command
      def initialize(address, data)
        super(Types::WRITE_VOLATILE_W, [ address, :u32 ], [ data.size / 2, :u8 ], [ data, :blob ])
      end
    end

    class WriteVolatile32 < Command
      def initialize(address, data)
        super(Types::WRITE_VOLATILE_D, [ address, :u32 ], [ data.size / 4, :u8 ], [ data, :blob ])
      end
    end

    class GetStatus < Command
      def initialize
        super(Types::GET_STATUS)
      end
    end

    class RequestLog < Command
      def initialize
        super(Types::LOG_REQUEST)
      end
    end

    class ReadNonVolatile < Command
      def initialize(address, size)
        super(Types::READ_NON_VOLATILE, [ address, :u16 ], [ size, :u8 ])
      end
    end

    class GetDiagVersion < Command
      def initialize
        super(Types::GET_DIAG_VERSION)
      end
    end

    class GetTimestamp < Command
      def initialize
        super(Types::TIMESTAMP)
      end
    end

    class PeekMessage < Command
      def initialize(level)
        super(Types::GET_MESSAGE, [ level, :u16 ])
      end
    end

    class ChangeMode < Command
      def initialize(mode)
        super(Types::CHANGE_MODE, [ mode, :u16 ])
      end
    end

    class SwitchToDownloaderMode < Command
      def initialize
        super(Types::SWITCH_TO_DL_MODE)
      end
    end

    class DownloaderWriteVolatile < Command
      def initialize(address, size, data)
        super(Types::DL_WRITE, [ address, :u32be ], [ size, :u16be ], [ data, :blob ])
      end
    end

    class DownloaderExec < Command
      def initialize(address)
        super(Types::DL_EXEC, [ address, :u32be ])
      end
    end

    class DownloaderUnknown < Command
      def initialize
        super(0xc)
      end 
    end

    class GetExtendedBuildId < Command
      def initialize
        super(Types::EXTENDED_BUILD_ID)
      end
    end
  end

  attr_accessor :asynchronous

  def initialize(tty, logger = STDERR)
    fd = IO::sysopen(tty, Fcntl::O_RDWR | Fcntl::O_NOCTTY | Fcntl::O_NONBLOCK)
    @tty = IO.open(fd)
    @logger = logger
    @asynchronous = false
    @force_sync = true

    #if switch and exec_at_cmd("AT$QCDMG") != 'OK'
    #  raise DiagTaskClientError, "Cannot switch to diagnostic mode"
    #end

    flush_input
  end

  def enter_full_sync_mode
    @force_sync = true
  end

  def leave_full_sync_mode
    @force_sync = false
    
    if @async_watch and not @asynchronous
      @asynchronous = true
      @async_watch.run
    end
  end

  def wait_for_async_packets(&callback)
    #Thread.abort_on_exception = true
    @asynchronous = true
    @force_sync = false
    @async_watch = Thread.start(callback) do |cb|
      loop do
        begin
          unless @asynchronous
            #log 'Stopping async'
            Thread.stop
            #log 'Resuming async'
            next
          end

          packet = read_diag_response

          if packet
            log("Received asynchronous packet:\n" + packet.hexdump)
            cb[packet]
          end
        rescue Exception => e
          #puts e.message
        end
      end
    end
  end

  def close
    @tty.close
    @logger.close unless [STDOUT,STDERR].include? @logger
  end

  def get_version
    packet = exec_diag_cmd Command::GetVersion.new

    {
      :compilation_date => packet[1,11],
      :compilation_time => packet[12,8],
      :release_date => packet[20,11],
      :release_time => packet[31,8],
      :version_directory => packet[39,8],
      :station_class_mark => packet[47,1].unpack('C')[0],
      :mobile_cai_revision => packet[48,1].unpack('C')[0],
      :mobile_model => packet[49,1].unpack('C')[0],
      :mobile_fw_revision => packet[50,2],
      :slot_cycle_index => packet[52,1].unpack('C')[0],
      :msm_version => packet[53,2]
    }
  end

  def get_extended_build_id
    packet = exec_diag_cmd Command::GetExtendedBuildId.new
  
    {
      :hw_version => packet[4,4].unpack('V')[0].to_s(16),
      :mob_model => packet[8,4],
      :mob_sw_rev => packet[12..-1].unpack('Z*')[0]
    }
  end

  def get_serial_number
    packet = exec_diag_cmd Command::GetSerialNumber.new

    packet[1,4].unpack("V")[0].to_s(16).rjust(8,'0').upcase!
  end

  def get_timestamp
    packet = exec_diag_cmd Command::GetTimestamp.new

    packet[1,8].unpack('Q')[0]
  end

  def read_log
    packet = exec_diag_cmd Command::RequestLog.new
    
    packet.hexdump
  end

  def peek_messages(level = MessageLevel::LOW)
    packet = exec_diag_cmd Command::PeekMessage.new(level)

    { :quantity => packet[1,2].unpack('v')[0],
      :drop_count => packet[3, 4].unpack('V')[0],
      :total_msgs => packet[7, 4].unpack('V')[0],
      :msg_level => packet[11, 1].unpack('C')[0],
      :filename => packet[12, 13].unpack('Z*')[0],
      :line_num => packet[25, 2].unpack('v')[0],
      :fmt_string => packet[27, 40].unpack('Z*')[0],
      :code1 => packet[67, 4].unpack('V')[0],
      :code2 => packet[71, 4].unpack('V')[0],
      :code3 => packet[75, 4].unpack('V')[0],
      :timestamp => packet[79, 8]
    }
  end

  def readv(address, size)
    data = ''
    consumed = 0

    while consumed < size
      remaining = size - consumed
      if remaining >= 16
        read_size = 4
      else
        read_size = (remaining + 3) >> 2
      end

      begin
        packet = exec_diag_cmd Command::ReadVolatile32.new(address, read_size)
        data << packet[7, read_size * 4]
      rescue InvalidDiagPacketError => e
        log(e.message)
        data << "\xDE\xAD\xBE\xEF" * read_size
      end

      consumed += read_size * 4
      address += read_size * 4
    end

    data[0, size]
  end

  def writev(address, data)
    consumed = 0

    while consumed < data.size
      remaining = data.size - consumed
      if remaining >= 4
        write_size = 4
      else
        write_size = remaining
      end

      packet = exec_diag_cmd Command::WriteVolatile8.new(address, data[consumed, write_size])

      consumed += write_size
      address += write_size
    end
  end

  def readnv(address, size)
    data = ''
    consumed = 0

    while consumed < size
      remaining = size - consumed
      if remaining > 32
        read_size = 32
      else
        read_size = remaining
      end

      packet = exec_diag_cmd Command::ReadNonVolatile.new(address, read_size)

      data << packet[4, read_size]

      consumed += read_size
      address += read_size
    end

    data[0, size]
  end

  def get_diag_version
    packet = exec_diag_cmd Command::GetDiagVersion.new

    packet[1,2].unpack('v')[0]
  end

  def set_mode(mode)
    exec_diag_cmd Command::ChangeMode.new(mode)
  end

  def switch_to_downloader
    exec_diag_cmd Command.new(0x0c)
    set_mode Modes::OFFLINE_DIGITAL
    
    packet = exec_diag_cmd Command::SwitchToDownloaderMode.new
    raise DiagTaskClientError, "Cannot switch to downloader mode" if packet[0,1] != "\x3a"

    @tty.syswrite Command.new(0x09).to_s
    exec_diag_cmd Command.new(0x0c)
    @tty.syswrite Command.new(0x09).to_s
    exec_diag_cmd Command.new(0x07)
  end

  def upload_code(path, address)
    data = File.read(path)
    i = 0

    while i < data.size
      if data.size - i >= 0x400
        blocksize = 0x400
      else
        blocksize = data.size - i
      end

      @tty.syswrite Command.new(0x09).to_s
      packet = exec_diag_cmd Command::DownloaderWriteVolatile.new(address, blocksize, data[i, blocksize]), :with_prefix => true
      raise DiagTaskClientError, "Cannot write to memory" if packet[0,1] != "\x02"

      address += blocksize
      i += blocksize
    end

    true
  end

  def execute_code(entrypoint)
    @tty.syswrite Command.new(0x09).to_s
    packet = exec_diag_cmd Command::DownloaderExec.new(entrypoint), :with_prefix => true
    raise DiagTaskClientError, "Cannot exec code" if packet[0,1] != "\x02"

    true
  end

  def send_raw_cmd(cmd, params = {})
    exec_diag_cmd(cmd, params)
  end

  def read_raw_response(params = {})
    read_diag_response(params)
  end

  private

  def log(msg)
    @logger.puts("LOG: #{msg}") if @logger
  end

  def flush_input
    loop do
      begin
        @tty.sysread 1024
      rescue Errno::EAGAIN
        break
      end
    end
  end

  def exec_at_cmd(cmd)
    flush_input

    log(">>> #{cmd}")
    @tty.write(cmd + AT_EOL)
    @tty.readline # remove echo
    
    response = @tty.readline
    log("<<< #{response}")

    response.chomp
  end

  def exec_diag_cmd(cmd, params = {})
    data = cmd.to_s
    tries = 0

    if @asynchronous
      @asynchronous = false # switch to synchronous mode
      @async_watch.raise 'Sync mode'
      Thread.pass
      sleep(0.05) until @async_watch.stop?
    end

    log("Sending diagnostic command:\n" + data.hexdump)
    begin
      @tty.syswrite(data)
      packet = read_diag_response(params)
    rescue InvalidDiagPacketError
      tries += 1
      retry if tries < 5
      raise
    end

    if @async_watch and not @force_sync
      @asynchronous = true
      @async_watch.run
    end

    packet
  end

  def read_diag_response(params = {})
    packet = ''
    tries = 0

    options =
    {
      :with_prefix => false,
      :with_crc => true
    }.update params
      
    if options[:with_prefix]
      begin 
        c = @tty.sysread(1)

        raise InvalidDiagPacketError, "Not a prefix : #{c.inspect}" if c != DIAG_EOL
      rescue Errno::EAGAIN, EOFError
        tries += 1
        if tries < READ_MAX_RETRY
          sleep(0.05)
          retry
        else
          log("Cannot read data from tty")
          raise
        end
      end
    end

    tries = 0
    begin
      while (c = @tty.sysread(1)) != DIAG_EOL
        packet << c
      end
    rescue Errno::EAGAIN, EOFError
      tries += 1
      if tries < READ_MAX_RETRY
        sleep(0.05)
        retry
      else
        log("Cannot read data from tty")
        raise
      end
    end

    packet.gsub!("\x7d\x5e", "\x7e")
    packet.gsub!("\x7d\x5d", "\x7d")

    log("Received diagnostic response:\n" + packet.hexdump)

    if options[:with_crc]
      crc = packet[-2,2].unpack("v")[0] 
      if crc != CRC.compute(packet[0, packet.size - 2])
        log("Received packet has invalid CRC")
        raise InvalidDiagPacketError, packet.hexdump
      end
      
      packet[0, packet.size - 2]
    else
      packet[0, packet.size]
    end
    
  end
end

