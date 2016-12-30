# Logcleaner
Two log cleaner/dumper scripts:
  one for UTMP logfiles
  one for LASTLOG logfiles


# clear_utmp
```
./clear_utmp.rb -h
Usage: ./clear_utmp.rb [options]
    -f, --file FILE                  File
    -s, --string STRING              String
    -r, --replace REPLACE            Replace
    -e, --edit                       Edit file
    -d, --dump                       Dump file
    -t, --time-start TIME            Starttime
    -T, --time-stop TIME             Stoptime
    -h, --help                       Displays Help

```

# clear_lastlog
```
./clear_lastlog.rb -h
Usage: ./clear_lastlog.rb [options]
    -f, --file FILE                  File
    -u, --user USERNAME              User
    -s, --search STRING              Search
    -n, --new TIME                   Newtime
    -r, --replace REPLACE            Replace
    -d, --dump                       Dump file
    -h, --help                       Displays Help

```

# installation
Installing ruby gem "bindata"
`gem install --user bindata`


