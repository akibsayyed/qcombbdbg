#!/usr/bin/env ruby

$: << '..'

require 'pp'
require 'diagtaskclient'
require 'stringio'

DEFAULT_TTY = '/dev/ttyHS2'
TTY = ARGV[0] || DEFAULT_TTY
diag = DiagTaskClient.new(TTY, StringIO.new)

if version = diag.get_version and build = diag.get_extended_build_id 
  puts "Mobile software revision:".ljust(40, ' ') + build[:mob_sw_rev]
  puts "Hardware revision:".ljust(40, ' ') +  build[:hw_version]
  puts "Mobile model:".ljust(40, ' ') + version[:mobile_model].to_s
  puts "Diagnostic version:".ljust(40, ' ') + diag.get_diag_version.to_s
  puts "Mobile common air interface revision:".ljust(40, ' ') + version[:mobile_cai_revision].to_s
  puts "Station class mark:".ljust(40, ' ') + version[:station_class_mark].to_s
  puts "Slot cycle index:".ljust(40, ' ') + version[:slot_cycle_index].to_s
  puts "Version directory:".ljust(40, ' ') +  version[:version_directory]
  puts "Release date:".ljust(40, ' ') + version[:release_date] + ' ' + version[:release_time]
  puts "System compilation date:".ljust(40, ' ') + version[:compilation_date] + ' ' + version[:compilation_time]
end

