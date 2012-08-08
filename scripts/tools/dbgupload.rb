#!/usr/bin/env ruby

=begin

= File
	dbgupload.rb

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

require 'pp'
require 'diagtaskclient'

PRELOADER_PATH = "../../src/preloader"
DEBUGGER_PATH = "../../src/qcombbdbg"

TTY = ARGV[0] || '/dev/ttyHS2'
abort "Cannot find TTY device #{TTY}, exiting." unless File.exists? TTY

require 'stringio'
@diag = DiagTaskClient.new(TTY)

PAYLOAD_ADDR = 0x01d0_0000 # Where the debugger is uploaded
PRELOAD_ADDR = 0x01e0_0000 # Where the preloader is uploaded
NEW_CMD_TABLE_ADDR = 0x1c0_0000 # Where the diagnostic command table is relocated
LOOPBACK_CMD = 0x7b


#
# Supported firmware revisions.
#
DEVICE_OFFSETS =
{
  "2.5.13Hd" =>
  {
    :cmd_root_table_addr => 0xef09c4,
  },

  "2.5.21Hd" =>
  {
    :cmd_root_table_addr => 0xef09c4,
  },

  "2.5.23Hd" =>
  {
    :cmd_root_table_addr => 0xef49c4,
  }
}

#
# Get firmware version
#
version = @diag.get_extended_build_id[:mob_sw_rev]
STDERR.puts "[*] Got firmware revision : #{version}"

unless DEVICE_OFFSETS.include?(version)
  abort "Unknown device revision (#{version}), aborting."
end

#
# Compile the preloader and the debugger
#
system "make -C #{PRELOADER_PATH} clean"
system "make -C #{PRELOADER_PATH} MODEL=#{version}"
system "make -C #{DEBUGGER_PATH} clean"
system "make -C #{DEBUGGER_PATH} MODEL=#{version}"

offsets = DEVICE_OFFSETS[version]

#
# Copy preloader stub
#
if RUBY_VERSION < '1.9'
  @diag.writev(PRELOAD_ADDR, File.read("#{PRELOADER_PATH}/preloader.bin"))
else
  @diag.writev(PRELOAD_ADDR, File.read("#{PRELOADER_PATH}/preloader.bin", :encoding => 'binary'))
end

def patch_command(root_table, cmd, routine)
  while (cmd_set_addr = @diag.readv(root_table, 4).unpack('V')[0]) != 0
    cmd_set = @diag.readv(cmd_set_addr, 16)
    if cmd_set[2, 4] == "\xff\x00\xff\x00" # Standard command
      num_cmds = cmd_set[6,2].unpack('v')[0]
      cmd_array_addr = cmd_set[12,4].unpack('V')[0]
      cmd_array = @diag.readv(cmd_array_addr, num_cmds * 8)

      num_cmds.times do |i|
        cmd_def = cmd_array[i * 8, 8]
        if cmd_def[0, 2].unpack('v')[0] == cmd # We found it!
          cmd_set[12, 4] = [ NEW_CMD_TABLE_ADDR + 16 ].pack('V') # move structures next to each other
          cmd_array[i * 8 + 4, 4] = [ routine | 1 ].pack('V') # redirect command handler to our routine
          
          # Write the new command handler set
          @diag.writev(NEW_CMD_TABLE_ADDR, cmd_set + cmd_array)  

          # Redirect the command table
          @diag.writev(root_table, [ NEW_CMD_TABLE_ADDR ].pack('V'))

          return NEW_CMD_TABLE_ADDR + 16 + i * 8 + 4 # address of routine
        end
      end
    end

    root_table += 4
  end

  nil
end

handler_addr = patch_command(offsets[:cmd_root_table_addr], LOOPBACK_CMD, PRELOAD_ADDR)
fail "Cannot install DIAG command hook" unless handler_addr

#
# We can now use the preloader function to inject the real payload faster.
#

if RUBY_VERSION < '1.9'
  payload = File.read("#{DEBUGGER_PATH}/qcombbdbg.bin")
else
  payload = File.read("#{DEBUGGER_PATH}/qcombbdbg.bin", :encoding => 'binary')
end

BLOCK_SIZE = 512 # Copy the debugger by block of 512 bytes
blocks = payload.size / BLOCK_SIZE
blocks += 1 if payload.size % BLOCK_SIZE != 0

#
# Copy debugger payload at final address
#
blocks.times do |i|
  @diag.send_raw_cmd DiagTaskClient::Command.new(0x7b, 
    [ 8, :u8 ], 
    [ PAYLOAD_ADDR + i*BLOCK_SIZE, :u32 ],
    [ payload[i*BLOCK_SIZE, BLOCK_SIZE], :blob ]
  )
end

#
# Patch cmd to point at final payload
#
@diag.writev(handler_addr, [ PAYLOAD_ADDR | 1 ].pack("V"))

