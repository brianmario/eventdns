def daemon_path(username, name)
    "/daemondrop/#{username}/#{name}"
end

USER = 'progrium'
NAME = 'eventdns'
path = daemon_path(USER, NAME)
pid_file = "#{path}/pid/#{NAME}.pid"
command = "/usr/bin/env ruby #{path}/eventdns.rb"

God.pid_file_directory = pid_file

God.watch do |w|
  w.name = "#{USER}-#{NAME}"
  w.interval = 30.seconds # default      
  w.start = "start-stop-daemon --quiet --pidfile #{pid_file} --exec #{command} --start"
  w.stop  = "start-stop-daemon --quiet --pidfile #{pid_file} --exec #{command} --stop"
  w.start_grace = 10.seconds
  w.restart_grace = 10.seconds
  w.pid_file = pid_file
  
  w.behavior(:clean_pid_file)

  w.start_if do |start|
    start.condition(:process_running) do |c|
      c.interval = 5.seconds
      c.running = false
    end
  end
  
  # lifecycle
  w.lifecycle do |on|
    on.condition(:flapping) do |c|
      c.to_state = [:start, :restart]
      c.times = 5
      c.within = 5.minute
      c.transition = :unmonitored
      c.retry_in = 10.minutes
      c.retry_times = 5
      c.retry_within = 2.hours
    end
  end
end
