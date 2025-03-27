# Schedule n events and also recursively invoke n events.
global n = 6000000;

redef exit_only_after_terminate = T;

global sum = 0;

event e(n: count) {
	sum += n;
}

event more(n: count)
	{
	if ( n == 0 )
		{
		terminate();
		return;
		}

	schedule 0.1usec { e(n - 1) };
	event more(n - 1);
	}

event zeek_init()
	{
	event more(n);
	}

event zeek_done()
	{
	print sum;
	}
