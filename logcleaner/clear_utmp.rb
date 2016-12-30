#!/usr/bin/ruby
#
# Version: 0.1
#
#

require 'optparse'
require 'pp'
require 'bindata'
require 'time'
require 'ipaddr'
require 'tempfile'


options = {
  file: nil,
  string: nil,
  replace: nil,
  edit: false,
  dump: false,
  time_min: nil,
  time_max: nil
}

parser = OptionParser.new do|opts|
  opts.banner = "Usage: #{__FILE__} [options]"
  opts.on('-f', '--file FILE', 'File') do |file|
    options[:file] = file
  end
  opts.on('-s', '--string STRING', 'String') do |string|
    options[:string] = string
  end
  opts.on('-r', '--replace REPLACE', 'Replace') do |replace|
    options[:replace] = replace
  end
  opts.on('-e', '--edit', 'Edit file') do |edit|
    options[:edit] = edit
  end
  opts.on('-d', '--dump', 'Dump file') do |dump|
    options[:dump] = dump
  end

  opts.on('-t', '--time-start TIME', 'Starttime') do |time|
    options[:time_min] = time
  end
  opts.on('-T', '--time-stop TIME', 'Stoptime') do |time|
    options[:time_max] = time
  end


  opts.on('-h', '--help', 'Displays Help') do
    puts opts
    exit
  end
end

parser.parse!

def permissions?(file)
  if File.readable?(file) && File.writable?(file)
    true
  else
    false
  end
end

def filesize(file)
  File.size file
end

def rand_text_alpha(size = 24)
  ([*('a'..'z'), *('0'..'9'), *('A'..'Z')] - %w(0 1 I O)).sample(size).join
end

def write_file(file, data)
  f = File.open(file, "w")
  f.print data
  f.close
end

def read_file(file, _ignore1 = false, _ignore2 = false)
  File.read(file)
end

 def run(options)
   time_min = nil
    time_max = nil


    file = options[:file].to_s.strip
    if file.empty?
      puts('Error: no file given. Try -h for options')
      exit -1
    end

    dump = options[:dump]
    if dump
      dump_utmp(file)
      return
    end

    string = options[:string].to_s.strip
    if (string.empty?) && (options[:edit] == false) && (options[:time_min].nil? or options[:time_max].nil?)
      puts("Error: string is empty but needed")
      exit -1
    end
    replace = options[:replace].to_s.strip
    localedit = options[:edit]

    if options[:time_min] && options[:time_max]
      begin
        time_min = Time.parse(options[:time_min])
        time_max = Time.parse(options[:time_max])
      rescue
        puts "Wrong time format. Information about format: Time.parse (http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse)"
        puts "Time given for Min time: #{options[:time_min].dump}\n Time given for Max time: #{options[:time_max].dump}"
        puts "Error: use another time format!"
        exit -1
      end
    end


      ################
      # check file permissions
      unless  permissions?(file)
        puts "Error: need read and write permissions for #{file}"
        exit -1
      end
      ################
      # size check/warning
      size = filesize(file)
      if size.nil? || size == 0
        puts "#{file}: not readable or empty"
        return
      elsif size > 1024 * 1024 * 1024 # 1G
        puts "#{file}: file size (#{size}) more than 1 G: This would fail and crash the session! Cannot download"
        puts "#{file} will be igroned due to this size"
        return
      elsif size > 1024 * 1024 * 100  # 100 MB
        puts "#{file}: file size (#{size}) more than 100Mb: This will need long time and lot of recourses"
        puts "#{file} will be igroned due to this size"
        return
      elsif size > 1024 * 1024 * 10           # 10 MB
        # 10 MB
        puts "#{file}: file size (#{size}) more than 10Mb: This will need a while"
      elsif size > 1024 * 1024                                # 1MB
        puts "#{file}: file size (#{size}) more than 1Mb: This might need some time"
      else                                                                                                            # less
        # OK
      end

      ################
      clean = clear_utmp(file, string, replace, localedit, time_min, time_max)
      if clean.nil?
        puts "Error: empty output"
        return
      end
      ##################
      # overwrite file
      random_data = rand_text_alpha(size)
      random_data << "\x00" * 256
      write_file(file, random_data)
      ##################
      # write file
      write_file(file, clean)
      #
  end

 def get_utmp_type(logfile)
   [UtmpLinux.new, UtmpFreeBSD.new, UtmpBSD.new].each do |utmp|
     next unless utmp.size_ok?(logfile.size)
      if utmp.check_structure(logfile)
        puts utmp.class
        return utmp
      end
   end
    nil
  end

 def dump_utmp(file)
   logfile = StringIO.new(read_file(file, true, false))
    utmp = get_utmp_type(logfile)
    if utmp.nil?
      print_error "Unkown UTMP structure for #{file}"
      return
    end
    utmp.each_entry(logfile) do | utmp, data |
      puts utmp.print_entry(data)
    end
 end


 def clear_utmp(file, string, replace = nil, do_edit = false, time_min = nil, time_max = nil)
   rx = Regexp.new(string)
    clean_data = ''
    editor = ENV['EDITOR'] || 'vi'
    logfile = StringIO.new(read_file(file, true, false))
    edit_file = Tempfile.new('utmp')
    utmp = get_utmp_type(logfile)
    if utmp.nil?
      print_error "Unkown UTMP structure for #{file}"
      return
    end

    tmpdata = StringIO.new
    if do_edit == true
      edit_file.print utmp.print_lines(logfile)
      edit_file.close
      system("#{editor} #{edit_file.path}")
      tmpdata = StringIO.new(::File.read edit_file.path)
    else
      utmp.print_lines(logfile).each_line do |line|
        if rx.match(line)
          if (time_min) && (time_max)
            puts "Time: >= #{time_min}  and <= #{time_max}"
            puts "Line=|#{line}|"
            if line.match(/ut_tv_sec=\[(.*?)\]/)
              line_time = Regexp.last_match(1)
            elsif line.match(/ut_time=\[(.*?)\]/)
              line_time = Regexp.last_match(1)
            else
              line_time = nil
            end
            if line_time
              begin
                logtime = Time.parse(line_time)
                puts "Timestamp: #{logtime}"
                if (logtime >= time_min) && (logtime <= time_max)
                  puts "[REMOVED]"
                else
                  puts "Ignore: not in definded time window"
                  tmpdata << line
                end
              rescue
                puts "[ERROR] in parsing time (#{Regexp.last_match(1)})"
                tmpdata << line
              end
            else
              puts "[ERROR] in parsing time"
              tmpdata << line
            end
          elsif replace.to_s.empty?
            puts "Found string='#{string}' so I am removing this line:\n#{line}"
          else
            tmpdata << line.gsub(/#{string}/, replace)
          end
        else
          tmpdata << line
        end
      end
    end
    tmpdata.rewind
    new_data = utmp.text_to_bin(tmpdata)
    new_data.each do |utmp|
      clean_data << utmp.to_binary_s
    end
    clean_data
  end



class UtmpX

  attr_accessor :utmp

  class Utmp < BinData::Record
    endian		:little

  end

  def initialize
    @ut_type = {
      0 => "empty/unkown",
      1	=> "run-level",
      2	=> "boot time",
      3	=> "new time",
      4	=> "old time",
      5	=> "init process",
      6	=> "login process",
      7	=> "user process",
      8	=> "dead process",
      9	=> "accounting"
    }
    @fields = ["ut_type", "ut_pid", "ut_line", "ut_name", "ut_id", "ut_user", "ut_host", "ut_exit", "ut_tv_sec", "ut_time", "ut_tv_usec", "ut_session", "ut_addr_v6", "ut_addr", "unused"]

  end


  def utmp_size
    @utmp.to_binary_s.length
  end

#	def type_ok?(file)
#		filesize = ::File.size(file)
#		if (filesize % utmp_size) == 0
#			true
#		else
#			false
#		end
#	end

    def size_ok?(filesize)
      if (filesize % utmp_size) == 0
        true
      else
        false
      end
  end

  def ip_to_string(struct)
    if struct.base_respond_to? :ut_addr_v6
      data = struct.ut_addr_v6
    else
      data = struct.ut_addr
    end
    if (data[0] == 0) && (data[1] == 0) && (data[2] == 0) && (data[3] == 0)
      "none"
    elsif (data[0] > 0) && (data[1] == 0) && (data[2] == 0) && (data[3] == 0)
      # IPv4
      "IPv4 #{IPAddr.new(data[0], Socket::AF_INET)}"
    else
      number = (data[0] << 96) + (data[1] << 64) + (data[2] << 32) + data[4]
      "IPv6 #{IPAddr.new(number, Socket::AF_INET6)}"
    end
  end

  def string_to_ip(string)
    return [0, 0, 0, 0] if (string.nil?) || (string == 'none')
    string.gsub!("IPv4", "")
    string.gsub!("IPv6", "")
    string.strip!
    num = IPAddr.new(string).to_i
    if num < 9999999999
      # ipv4
      [num, 0, 0, 0]
    else
      low_1 = num & 0xFFFFFFFF
      low_2 = (num >> 32) & 0xFFFFFFFF
      low_3 = (num >> 64) & 0xFFFFFFFF
      low_4 = (num >> 96) & 0xFFFFFFFF
      [low_4, low_3, low_2, low_1]
    end
  end


  def time_to_string(data)
    Time.at(data.ut_tv_sec).to_s
  end

  def tvtime_to_string(data)
    Time.at(data.ut_time).to_s
  end

  def string_to_time(string)
    Time.parse(string).to_i
  end

  def type_to_string(data)
    @ut_type[data.ut_type]
  end

  def string_to_type(string)
    @ut_type.each_pair do |key, value|
      return key if string == value
    end
      string.to_i
  end

  def dump_entry(data)
    out = {}
    out["ut_type"]		= type_to_string(data)	if data.respond_to? :ut_type
    out["ut_pid"]			= data.ut_pid						if data.respond_to? :ut_pid
    out["ut_line"]		= data.ut_line					if data.respond_to? :ut_line
    out["ut_id"]			= data.ut_id						if data.respond_to? :ut_id
    out["ut_user"]		= data.ut_user					if data.respond_to? :ut_user
    out["ut_name"]		= data.ut_name					if data.respond_to? :ut_name
    out["ut_host"]		= data.ut_host					if data.respond_to? :ut_host
    out["ut_exit"]		= data.ut_exit					if data.respond_to? :ut_exit
    out["ut_tv_sec"]	= time_to_string(data)	if data.respond_to? :ut_tv_sec
    out["ut_time"]		= tvtime_to_string(data)	if data.respond_to? :ut_time
    out["ut_tv_usec"] = data.ut_tv_usec				if data.respond_to? :ut_tv_usec
    out["ut_session"] = data.ut_session				if data.respond_to? :ut_session
    out["ut_addr_v6"]	= ip_to_string(data)		if data.respond_to? :ut_addr_v6
    out["unused"]			= data.unused						if data.respond_to? :unused
    out
  end

  def create_entry(data)
    tmp = dump_entry(data)
    new_utmp = hash2data(tmp)
    new_utmp
  end

  def hash2data(data)
    new_utmp = create_utmp
    new_utmp.ut_type = string_to_type(data["ut_type"])			if new_utmp.respond_to? :ut_type
    new_utmp.ut_pid = data["ut_pid"]												if new_utmp.respond_to? :ut_pid
    new_utmp.ut_line = data["ut_line"]											if new_utmp.respond_to? :ut_line
    new_utmp.ut_id = data["ut_id"]													if new_utmp.respond_to? :ut_id
    new_utmp.ut_user = data["ut_user"]											if new_utmp.respond_to? :ut_user
    new_utmp.ut_name = data["ut_name"]											if new_utmp.respond_to? :ut_name
    new_utmp.ut_host = data["ut_host"]											if new_utmp.respond_to? :ut_host
    new_utmp.ut_exit = data["ut_exit"]											if new_utmp.respond_to? :ut_exit
    new_utmp.ut_time = string_to_time(data["ut_time"])			if new_utmp.respond_to? :ut_time
    new_utmp.ut_tv_sec = string_to_time(data["ut_tv_sec"])	if new_utmp.respond_to? :ut_tv_sec
    new_utmp.ut_tv_usec = data["ut_tv_usec"]								if new_utmp.respond_to? :ut_tv_usec
    new_utmp.ut_session = data["ut_session"]								if new_utmp.respond_to? :ut_session
    new_utmp.ut_addr_v6 = string_to_ip(data["ut_addr_v6"])	if new_utmp.respond_to? :ut_addr_v6
    new_utmp.ut_addr = string_to_ip(data["ut_addr"])				if new_utmp.respond_to? :ut_addr
    new_utmp.unused = data["unused"]												if new_utmp.respond_to? :unused
    new_utmp
  end

  def print_entry(data)
    out = "==========================================\n"
    tmp = dump_entry(data)
    tmp.each_pair do |key, value|
      if (key == 'ut_line') || (key == 'ut_user') || (key == 'ut_host') || (key == 'unused') || (key == 'ut_name')
        value = value.delete "\x00"
      end
      out << sprintf("%s%-20s [%-40s]\n", '', key, value)
    end
    out << "\n"
    out
  end

  def print_line(data)
    out = ''
    tmp = dump_entry(data)
    tmp.each_pair do |key, value|
      if (key == 'ut_line') || (key == 'ut_user') || (key == 'ut_host') || (key == 'unused') || (key == 'ut_name')
        value.delete! "\x00"
      end

      out << sprintf(" %s=[%10s] |", key, value)
    end
    out << "\n"
    out
  end


  def read_entry(io)
    @utmp.read(io)
  end

  def each_entry(io)
    until io.eof?
      data = read_entry(io)
      yield(self, data)
    end
    io.seek 0
  end

  def print_all(io)
    out = ''
    each_entry(io) do | utmp, data |
      out << utmp.print_entry(data)
    end
    out
  end

  def print_lines(io)
    out = ""
    @fields.each do |tmp|
      next unless @utmp.base_respond_to? tmp.to_sym
      out << sprintf(" %s=[%10s] |", tmp, '')
    end
    out << "\n"
    out << "-" * out.length
    out << "\n"
    each_entry(io) do | utmp, data |
      out << utmp.print_line(data)
    end
    out
  end

  def to_text(io)
    print_lines(io)
  end

  def text_to_bin(io)
    data = []
    io.each_line do |line|
      line = line.force_encoding(Encoding::BINARY)
      next if line.start_with? "IGNORE_LINE"
      out = {}
      ignore = false
      @fields.each do |tmp|
        if line.match(/#{tmp}=\[(.*?)\]/)
          out[tmp] = Regexp.last_match(1)
          out[tmp].strip!
        else
        # puts "Not found: #{tmp}"
        #	ignore = true
        end
      end
      ["ut_pid", "ut_id", "ut_exit", "ut_tv_usec", "ut_session" ].each do |tmp|
        out[tmp] = out[tmp].to_i if out.key? tmp
      end
      if (out["ut_tv_sec"].to_s.empty?) && (out["ut_time"].to_s.empty?)
        # puts "No Time"
        ignore = true
      end
      if ignore == true
        # puts "Ignore"
        next
      end
      new_utmp = hash2data(out)
      data << new_utmp
    end
    data
  end

  def check_structure(io)
    is_ok = true
    each_entry(io) do | utmp, data |
      new_utmp = utmp.create_entry(data)
      is_ok = false unless utmp.utmp.to_binary_s == new_utmp.to_binary_s
    end
    is_ok
  end

end

class UtmpLinux < UtmpX

  def initialize
    @utmp = create_utmp
    super
  end

  def create_utmp
    Utmp.new
  end

  class Utmp < BinData::Record
    endian		:little

    uint32		:ut_type
    uint32		:ut_pid
    string		:ut_line, length: 32
    uint32		:ut_id
    string		:ut_user, length: 32
    string		:ut_host, length: 256
    uint32		:ut_exit
    uint32le	:ut_tv_usec
    uint32le	:ut_tv_sec
    uint32		:ut_session
    array			:ut_addr_v6, type: :uint32be, initial_length: 4
    string		:unused, length: 20
  end
end

class UtmpFreeBSD < UtmpX

  def initialize
    @utmp = create_utmp
    super
  end

  def create_utmp
    Utmp.new
  end


  class Utmp < BinData::Record
    endian		:little
    string		:ut_line, length: 8
    string		:ut_name, length: 16
    string		:ut_host, length: 16
    uint32		:ut_time
  end
end

class UtmpBSD < UtmpX

  def initialize
    @utmp = create_utmp
    super
  end

  def create_utmp
    Utmp.new
  end

  class Utmp < BinData::Record
    endian		:little

    uint32		:ut_type
    uint32		:ut_pid
    string		:ut_line, length: 16
    string		:ut_id, length: 4
    uint32le	:ut_time
    string		:ut_user, length: 16
    string		:ut_host, length: 16
    uint32le	:ut_addr

  end
end



 run(options)
