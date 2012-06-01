#!/usr/bin/env ruby

$: << '..'

require 'pp'
require 'diagtaskclient'
require 'stringio'

DEFAULT_TTY = '/dev/ttyHS2'
TTY = ARGV[0] || DEFAULT_TTY
diag = DiagTaskClient.new(TTY, StringIO.new)

trap('INT') do
  puts "Stopping..."
  diag.peek_messages(DiagTaskClient::MessageLevel::NONE)
  sleep 3
  exit
end

diag.peek_messages(DiagTaskClient::MessageLevel::LOW)

diag.wait_for_async_packets do |packet|
  msg = 
  { 
      :quantity => packet[1,2].unpack('v')[0],
      :drop_count => packet[3, 4].unpack('V')[0],
      :total_msgs => packet[7, 4].unpack('V')[0],
      :msg_level => packet[11, 1].unpack('C')[0],
      :filename => packet[12, 13].unpack('Z*')[0],
      :line_num => packet[25, 2].unpack('v')[0],
      :fmt_string => packet[27, 40].unpack('Z*')[0],
      :code1 => packet[67, 4].unpack('V')[0],
      :code2 => packet[71, 4].unpack('V')[0],
      :code3 => packet[75, 4].unpack('V')[0],
      :timestamp => packet[79, 8].unpack('Q')[0] >> 16
  }

  level =
    case msg[:msg_level]
      when DiagTaskClient::MessageLevel::NONE then  '<NONE> '
      when DiagTaskClient::MessageLevel::LOW then   '<LOW>  '
      when DiagTaskClient::MessageLevel::MED then   '<MED>  '
      when DiagTaskClient::MessageLevel::HIGH then  '<HIGH> '
      when DiagTaskClient::MessageLevel::ERROR then '<ERROR>'
      when DiagTaskClient::MessageLevel::FATAL then '<FATAL>'
    end

  puts "[TS #{msg[:timestamp]}] #{level} (#{msg[:filename]}:#{msg[:line_num]}) #{msg[:fmt_string]}" % [
    msg[:code1],
    msg[:code2],
    msg[:code3],
  ]
end

loop do
  sleep 1
end

