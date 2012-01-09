#!/usr/bin/env ruby

$: << '..'

require 'pp'
require 'diagtaskclient'

PRELOADER_PATH = "../../src/preloader"
DEBUGGER_PATH = "../../src/qcombbdbg"

TTY = ARGV[0] || '/dev/ttyHS2'
@diag = DiagTaskClient.new(TTY)

PAYLOAD_ADDR = 0x01d0_0000
PRELOAD_ADDR = 0x01e0_0000
NEW_CMD_TABLE_ADDR = 0x1c0_0000

DEVICE_OFFSETS =
{
  "2.5.13Hd" =>
  {
    :cmd_root_table_addr => 0xef09c4,
    :cmd_hook_table_addr => 0x425788,
    :cmd_hook_table_size => 280
  },

  "2.5.21Hd" =>
  {
    :cmd_root_table_addr => 0xef09c4,
    :cmd_hook_table_addr => 0x425800,
    :cmd_hook_table_size => 280
  },

  "2.5.23Hd" =>
  {
    :cmd_root_table_addr => 0xef49c4,
    :cmd_hook_table_addr => 0x42580c,
    :cmd_hook_table_size => 280
  }
}

#
# get firmware version
#
version = @diag.get_extended_build_id[:mob_sw_rev]
STDERR.puts "[*] Got firmware revision : #{version}"

unless DEVICE_OFFSETS.include?(version)
  abort "Unknown device revision (#{version}), aborting."
end

#
# compile the preloader and the debugger
#
system "make -C #{PRELOADER_PATH} MODEL=#{version}"
system "make -C #{DEBUGGER_PATH} MODEL=#{version}"

offsets = DEVICE_OFFSETS[version]

#
# copy stub
#
if RUBY_VERSION < '1.9'
  @diag.writev(PRELOAD_ADDR, File.read("#{PRELOADER_PATH}/preloader.bin"))
else
  @diag.writev(PRELOAD_ADDR, File.read("#{PRELOADER_PATH}/preloader.bin", :encoding => 'binary'))
end

#
# copy cmd table
#
cmd_table = @diag.readv(offsets[:cmd_hook_table_addr], offsets[:cmd_hook_table_size])
@diag.writev(NEW_CMD_TABLE_ADDR, cmd_table)

#patch cmd
@diag.writev(NEW_CMD_TABLE_ADDR + 0xc, [ NEW_CMD_TABLE_ADDR + 0x10 ].pack("V"))
@diag.writev(NEW_CMD_TABLE_ADDR + 0xbc, [ PRELOAD_ADDR + 1 ].pack("V"))

#
# redirect cmd table
#
@diag.writev(offsets[:cmd_root_table_addr] + 0x11 * 4, [ NEW_CMD_TABLE_ADDR ].pack("V"))

#
# We can now use the preloader function to inject the real payload faster.
#

if RUBY_VERSION < '1.9'
  payload = File.read("#{DEBUGGER_PATH}/qcombbdbg.bin")
else
  payload = File.read("#{DEBUGGER_PATH}/qcombbdbg.bin", :encoding => 'binary')
end

BLOCK_SIZE = 512
blocks = payload.size / BLOCK_SIZE
blocks += 1 if payload.size % BLOCK_SIZE != 0

#
# copy payload at final address
#
blocks.times do |i|
  @diag.send_raw_cmd DiagTaskClient::Command.new(0x7b, 
    [ 8, :u8 ], 
    [ PAYLOAD_ADDR + i*BLOCK_SIZE, :u32 ],
    [ payload[i*BLOCK_SIZE, BLOCK_SIZE], :blob ]
  )
end

#
# patch cmd to point at final payload
#
@diag.writev(NEW_CMD_TABLE_ADDR + 0xbc, [ PAYLOAD_ADDR + 1 ].pack("V"))

