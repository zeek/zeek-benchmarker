global n = 8000000;

redef exit_only_after_terminate = T;

global sum = 0;

event e(n: count)
	{
	if ( n == 0 )
		{
		terminate();
		return;
		}

	sum += n;

	event e(n -1);
}

event zeek_init()
	{
	event e(n);
	}

event zeek_done()
	{
	print sum;
	}
