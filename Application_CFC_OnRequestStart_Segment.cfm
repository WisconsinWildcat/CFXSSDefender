<!---
	The following segment goes in your Application.cfc's OnRequestStart segment. 
	
	You will likely need to change the path to where ColdFusion can find the 
	CrossScriptDefender component.
	
	Setting the encoding to utf-8 was also part of the recommendation of the
	penetration test company.
--->

		<!---
			******* CROSS-SITE-SCRIPTING DETERRENCE *******	
		--->
		<cfscript>
		    SetEncoding("form", "utf-8"); 
		    createObject("component", "yourpath.CrossScriptDefender").decodeScope(form);
		    SetEncoding("url", "utf-8"); 
		    createObject("component", "yourpath.CrossScriptDefender").decodeScope(URL);
		</cfscript>

