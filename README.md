portguard
=========
portguard is inspired by portsentry, and is similar with [portsentry](http://sourceforge.net/projects/sentrytools/files/portsentry%201.x/portsentry-1.2/), you can read portsentry's [documention](http://wiki.netbsd.org/nsps/portsentry.conf) to learn more about portguard.

It's written by golang, and the code base is much smaller than portsentry, so you can customize portguard easily as need;

And besides that, portguard's stateEngine is more powerful, it's easy to implement more detection rules.

install
=======
```shell
# set GOPATH as need
# export GOPATH=`pwd`
go get -u github.com/xjdrew/portguard
```

play
----
launch portguard in debug&tcp mode:
```
sudo bin/portguard -d -m="tcp" src/github.com/xjdrew/portguard/guard.conf
```
try shoot your unused port with fun!
