@load base/frameworks/logging

redef enum Log::ID += { LOG, LOG2 };

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
	Log::write(LOG2, Info($ts=network_time(), $msg=gmsg, $vec=gvec));

	if (--n > 0)
		event do_log(n);
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	Log::create_stream(LOG2, [$columns=Info, $path="test-2"]);
	event do_log(n);
	}
