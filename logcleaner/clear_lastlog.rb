#!/usr/bin/ruby
#
# version: 0.1
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
  user: nil,
  replace: nil,
  edit: false,
  dump: false
}

parser = OptionParser.new do|opts|
  opts.banner = "Usage: #{__FILE__} [options]"
  opts.on('-f', '--file FILE', 'File') do |file|
    options[:file] = file
  end
  opts.on('-u', '--user USERNAME', 'User') do |user|
    options[:user] = user
  end
  opts.on('-s', '--search STRING', 'Search') do |string|
    options[:search] = string
  end
  opts.on('-n', '--new TIME', 'Newtime') do |time|
    options[:new_time] = time
  end
  opts.on('-r', '--replace REPLACE', 'Replace') do |replace|
    options[:replace] = replace
  end
  opts.on('-d', '--dump', 'Dump file') do |dump|
    options[:dump] = dump
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

  file = options[:file].to_s.strip
    if file.empty?
      puts('Error: no file given. Try -h for options')
      exit -1
    end

    dump = options[:dump]
    if dump
      dump_lastlog(file)
      return
    end

    search = options[:search].to_s.strip
    username = options[:user].to_s.strip
    replace = options[:replace].to_s.strip

    if  options[:new_time]
      begin
        new_time = Time.parse(options[:new_time])
      rescue
        puts "Wrong time format. Information about format: Time.parse (http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse)"
         puts "Time given for New time: #{options[:new_time].dump}"
        puts "Error: use another time format!"
        exit -1
      end
    end

    ################
      # check file permissions
      unless  permissions?(file)
        puts "[ERROR] need read and write permissions for #{file}"
        exit
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

      clean = clear_lastlog(file, username, search, replace, new_time)
      if clean.nil?
        puts "[ERROR] empty output"
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


end

def dump_lastlog(file)
  logfile = StringIO.new(read_file(file, true, false))
  lastlog = LastLog.new
  lastlog.read_passwd(read_file("/etc/passwd", true, false))
  lastlog.each_entry(logfile) do | lastlog, uid |
    tmp = lastlog.print_entry(uid)
    if tmp.start_with?("uid=") && tmp.strip.end_with?("**Never logged in**")
      next
    end
    puts tmp
  end

end

def is_uid?(uid, username)
    begin
      user = Integer(username)
      uid == user
    rescue
      false
    end
end


def clear_lastlog(logfile, user = nil, search = nil, replace = nil, new_time = nil)
  clear_data = ''
  rx = Regexp.new(search) unless search.nil? || search.empty?
  logfile = StringIO.new(read_file(logfile, true, false))
  lastlog = LastLog.new
  # TODO: define a custom passwd file via option
  lastlog.read_passwd(read_file("/etc/passwd", true, false))
  lastlog.each_entry(logfile) do | lastlog, uid |
    needs_modify = false
    modifyed = false
    data = lastlog.dump_entry(uid)

    username = lastlog.uidmap[uid]
    if user
      username = lastlog.uidmap[uid]
      if (username == user) || is_uid?(uid, user)
        needs_modify = true
      end
    end
    if rx
      if rx.match(data["ll_line"]) || rx.match(data["ll_host"])
        puts "Regex /#{rx}/ matches"
        needs_modify = true
      end
    end

    if needs_modify == true
      puts "Need modify\tuid=#{uid} user=#{username} Line=|#{data["ll_line"]}| Host=|#{data["ll_host"]}| Time=#{data["ll_time"]}"
      if new_time
        puts "#{data["ll_time"]} -> #{new_time}"
        data["ll_time"] = new_time.to_i
        modifyed = true
      end
      if rx && !replace.empty?
        if rx.match(data["ll_line"])
          puts "#{data["ll_line"]} -> #{replace}"
          data["ll_line"] = replace
          modifyed = true
        end
        if rx.match(data["ll_host"])
          puts "#{data["ll_host"]} -> #{replace}"
          data["ll_host"] = replace
          modifyed = true
        end
      end

      if modifyed == true
        entry = lastlog.create_entry(data, uid)
      else
        entry = lastlog.create_lastlog
      end
    else
      entry = lastlog.create_entry(data, uid)
    end

    # clear_data.print entry.to_binary_s
    clear_data << entry.to_binary_s

  end
  # clear_data.rewind
  # clear_data.read
  clear_data
end


class LastLog
  attr_accessor :lastlog
  attr_accessor	:entries
  attr_accessor	:uidmap

  class LastLogStruct < BinData::Record
    endian		:little
      uint32		:ll_time
      string		:ll_line, length: 32
      string		:ll_host, length: 256
  end

  def initialize
    @lastlog = LastLogStruct.new
    @entries = {}
    @uidmap = {}
    @fields = ['ll_time', 'll_line', 'll_host', 'll_user']
  end


  def size
    @lastlog.to_binary_s.length
  end

  def size_ok?(file)
    filesize = ::File.size(file)
    if (filesize % size) == 0
      true
    else
      false
    end
  end

  def int_to_time(int)
    if int.nil? || int == 0
      "**Never logged in**"
    else
      Time.at(int).to_s
    end
  end

  def time_to_int(time)
    Time.parse(time).to_i
  end

  def read_uid(uid)
    lastlog.read(@entries[uid])
  end

  def dump_entry(uid)
    data =  read_uid(uid)
    out = {}
    out["ll_user"] = uid
    out["ll_time"] = data.ll_time								if data.respond_to? :ll_time
    out["ll_line"] = data.ll_line								if data.respond_to? :ll_line
    out["ll_host"] = data.ll_host								if data.respond_to? :ll_host
    out
  end

  def create_entry(data, uid)
    new_lastlog = hash2data(data, uid)
    new_lastlog
  end

  def create_lastlog
    LastLogStruct.new
  end

  def hash2data(data, _uid)
    new_lastlog = create_lastlog
    new_lastlog.ll_time = data["ll_time"]
    new_lastlog.ll_line = data["ll_line"]
    new_lastlog.ll_host = data["ll_host"]
    new_lastlog
  end

  def read_passwd(data = "")
    data.to_s.split("\n").each do |line|
      tmp = line.split(":")
      @uidmap[tmp[2].to_i] = tmp[0]
    end
  end

  def uid_to_username(uid)
      # if @uidmap.empty?
      #	 read_passwd()
      # end
    user = @uidmap[uid]
      if user.nil?
        "uid=#{uid}"
      else
        user
      end
  end


  def print_entry(uid)
    out = ''
    tmp = dump_entry(uid)
    ll_time =	 int_to_time(tmp['ll_time'])
    ll_user =  uid_to_username(tmp['ll_user'])
    # ll_user = uid
    ll_line =  tmp['ll_line'].delete "\x00"
    ll_host =  tmp['ll_host'].delete "\x00"
    out << sprintf("%-16s %-10s %-16s %-26s", ll_user, ll_line, ll_host, ll_time)
    out << "\n"
    out

  end

  def read_file(io)
    io.rewind
    i = 0
    until io.eof?
      data = @lastlog.read(io)
      @entries[i] = data.to_binary_s
      i += 1
    end
    i = 0
  end

  def each_entry(io)
    read_file(io) if @entries.empty?
    @entries.each_key do |uid|
      yield(self, uid)
    end
  end




end

run(options)
