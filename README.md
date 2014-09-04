CFXSSDefender
=============

ColdFusion Cross Site Scripting Defender

This XSS solution is offered free and unlicensed to all programmers. Updates and enhancements are encouraged, as this solution is not mature enough to be considered omniscient to all angles of attack that Cross Site Scripting should protect you from. With that said, PLEASE do not consider this to be a do-all, end-all, "perfect" solution for your XSS defense! It is merely another tool in your toolbox.

How it works is simple: as you run programs, it will examine the variables that you use. If the variable has never been seen before, it will attempt a simple clean of that variable, will log it into the table made for it (I use Microsoft SQL Server; you'll have to adapt it to fit your environment), and will carry on.

You will want to examine that table frequently. Items auto-logged are written with an itemtype in lower case, and I reccomend that you change them to upper-case as you investigate each one.

From that point on, your program will find that variable and read the itemtype and max length and will force your variable to conform to that; if it does not, it will shut the program down immediately; hence, your XSS protection.

Simple but effective.

One of the biggest FAILINGS of this system is the overhead it adds. When I designed it, there was not time to make it more efficient. We had a hard deadline to meet that meant a great deal to our bottom line, so speed was hyper-important to getting it done; efficiency had to take a back seat.

I would LOVE to have someone come up with a more efficient way of doing the SQL portion. Instead of a query for each and every variable each and every time, a group query of all known variables coming in would be a good start to making this more efficient.

Other methods of defense will come to fruition as more of you address this, and I'm excited to see what comes about.

Many of you asked for this on the Facebook ColdFusion Programmers group (https://www.facebook.com/groups/CFprogrammers/, August 13, 2014), so here it is now that I've gotten permission from my customer to do so.

Randy L. Smith
Saphea, Inc.
