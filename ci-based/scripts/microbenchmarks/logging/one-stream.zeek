@load base/frameworks/logging

redef enum Log::ID += { LOG };

type Info: record {
	ts: time &log;
	msg: string &log;
	vec: vector of count;
};

global n = 1000000;
global gmsg = "<msg>";
global gvec = vector(1, 2, 3);

event do_log(n: count)
	{
	Log::write(LOG, Info($ts=network_time(), $msg=gmsg, $vec=gvec));

	if (--n > 0)
		event do_log(n);
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	event do_log(n);
	}
