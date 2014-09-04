<cfcomponent displayname="Cross Script Defender" hint="I check scoped parameters for cross site scripting attacks" output="false">
	<!--- For CF10+ Prevention of XSS Cross Site Scripting attacks - this program satisfies the recommendation that each and every variable
		is examined for content and length. This program works well for legacy systems where returning to each program and updating the
		FORM and PARAMETERS/URL for each and every variable and defining them in each program would not be feasible, especially if time
		is tight. LIST and IGNORE need to have a test for standard XSS problems, though, like <script> and <img> with src in it, although
		if you have the ColdFusion Administrator "Enable Global Script Protection" checked that helps a lot in those cases.
		
		The code that self-heals also needs better tests; try to make a number without it being called a boolean or vice versa, same with
		dates and numerics. For now, this will suffice but the programmer or admin needs to stay on top of things. Self-healed items
		are inserted as lower-case itemtype; change them to upper case after you have reviewed it to show it's been examined and approved.
		 
		Item Type Definitions as used here:
		BOOLEAN    = 0, 1, t, f, true, false, y, n, yes, no; set the length to 5, but length is moot because it's ignored.
		CLEAR      = no matter what is in this field, clear it out! Length is ignored.
		DATE       = date, datetime, smalldatetime; set the length to 10 unless you also record time, but length is moot because it's is ignored.
		EMAIL      = allows all the characters allowed in an email, does NOT do an email perfect structure check; usually set to length of 100.
		FUSEACTION = allows the period and underscore but otherwise letters and numbers only; Length is ignored.
		IGNORE     = Really, ignore this field. Reserved for names like "fieldnames" and other internal items. Length is also ignored.
		INTEGER    = numbers only; intent is to further test integer down the road; usually set to length of 10.
		LIST       = anything but will remove < and >; intent is to beef up more in near future; usually set to length of 20000.
		NUMERIC    = numbers only; usually set to length of 10
		STRING     = letters or numbers only; strips spaces!!
		STRUCTURE  = must be a structure or it will be cleared; length ignored.
		TEXT       = anything but will remove the < symbol; usually set to length of 2000 to 8000.
		
		Key values can be entered into the SQL table as Keyname_* for variables that generate into
		a list of keyname_number pattern type variables.   
			Example: if you have, say, YEAR_2013, YEAR_2014, YEAR_2015, etc., you can put one definition 
				in the CrossScriptDefender table as YEAR_* and that will cover them all.
		
		The original structure of this program was stolen from David Epler's terrific primer on Cross-Site Scripting, which can be found
		at http://www.learncfinaweek.com/week1/cross_site_scripting__xss_/. We needed to beef that up quite a bit in order to pass our 
		penetration test and to record when errors happened in order to jump on them and fix them.. Thanks, Mr. Epler!
	--->
	<cffunction name="decodeScope" access="public" returntype="void" output="false">
		<cfargument name="scope" type="struct" required="true" />
		
		<cfset var key = "" />								        <!--- Working value of scoped item --->
		<cfset var beforeAndAfter = TRUE />					        <!--- If TRUE sends before and after dump of scope to developers; helps to find out what the issue is --->
		<cfset var ignoreScriptsList = "/somescriptnamehere.cfm" />	<!--- DO NOT record items from these programs --->
		<cfset var emailFrom = "somename@domain.com" /> <!--- When an error message is sent, which account is it coming FROM? --->
		<cfset var emailTo   = "somename@domain.com" /> <!--- When an error message is sent, which account is it going TO? --->
		<!--- These could also probably be handled better. The number in the name relates to the length of the variable; remove these examples before you start --->
		<cfset VAR seventeenString  = "SUNTIMECARDITEMNO,MONTIMECARDITEMNO,TUETIMECARDITEMNO,WEDTIMECARDITEMNO,THUTIMECARDITEMNO,FRITIMECARDITEMNO,SATTIMECARDITEMNO" />
		<cfset VAR fourteenString   = "TEST_THIS_FLAG" />
		<cfset VAR thirteenString   = "INVOICENUMBER" />
		<cfset VAR elevenString     = "EXPENSETEST,TESTSUPPORT" />
		<cfset VAR nineString       = "TESTORDER" />
		<cfset VAR sevenString      = "SUNDATE,MONDATE,TUEDATE,WEDDATE,THUDATE,FRIDATE,SATDATE,TEST_ID" />
		<cfset VAR threeString      = "SUN,MON,TUE,WED,THU,FRI,SAT,TOT" />
		<!--- Do NOT change this variables contents unless your boolean string is more stringent or more relaxed --->
		<cfset VAR booleanString    = "0,1,no,yes,true,false,y,n,t,f" />
			
		<!--- Dump written immediately in case a problem causes program to fail between before and after --->
		<cfif beforeAndAfter AND NOT listFindNoCase( ignoreScriptsList, CGI.Script_Name )>
			<cfset beforeScope = Duplicate(arguments.scope) />
			<cfinvoke method="recordResults" returnVariable="BAKey" targetCollection="#beforeScope#" />
		</cfif>
		
		<!---
			The following is NOT the best, most efficient way to do this. It is currently doing a query for EACH AND EVERY
			VARIABLE that passes through the system, including all FORM and URL variables. It was done this way in the
			interest of time as we had only a day to get something in place. It needs to be re-engineered to make it
			more efficient now, perhaps a loop to generate the query, then a loop to process the query results, but be sure
			to allow for when an item is NOT found so it errors / records that instance. 
		--->
		<cfloop collection="#arguments.scope#" item="key">
			<cfif IsSimpleValue(arguments.scope[key])>
				<cftry>
					<!--- do not allow multiple and mixed encodings, most likely an attack --->
					<cfset cleanKey = canonicalize( arguments.scope[key], false, false ) />
					<cfset wasCleanKey = cleanKey />
					<cfquery name="findMissingParameter" datasource="srm" >
						SELECT id, itemname, itemtype, itemmaxlength, samplevalues
							FROM [dbo].[CrossScriptDefender]
							WHERE itemname='#key#'
							<cfif listLen(key,"_") GT 1>
								<cfset llGo=TRUE />
								<cfif isNumeric( listGetAt(key,2,"_",TRUE) )>
									<cfif listLen(key,"_") GT 2>
										<cfif NOT isNumeric( listGetAt(key,3,"_",TRUE) )>
											<cfset llGo = FALSE />
										</cfif>
									</cfif>
									<cfif llGo>
										OR itemname = '#listGetAt(key,1,"_",TRUE)#_*'
									</cfif>
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 17 ) 
									AND ( listfindnocase( seventeenString, LEFT(TRIM(key),17) ) ) )>
								<cfif ISNUMERIC( MID(key,18,99) )>
									OR itemname = '#LEFT(TRIM(key),17)#*'
									OR itemname = '#LEFT(TRIM(key),17)#_*'
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 14 ) 
									AND ( listfindnocase( fourteenString, LEFT(TRIM(key),14) ) ) )>
								<cfif ISNUMERIC(MID(key,15,99) )>
									OR itemname = '#LEFT(TRIM(key),14)#*'
									OR itemname = '#LEFT(TRIM(key),14)#_*'
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 13 ) 
									AND ( listfindnocase( thirteenString, LEFT(TRIM(key),13) ) ) )>
								<cfif ISNUMERIC(MID(key,14,99) )>
									OR itemname = '#LEFT(TRIM(key),13)#*'
									OR itemname = '#LEFT(TRIM(key),13)#_*'
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 11 ) 
									AND ( listfindnocase( elevenString, LEFT(TRIM(key),11) ) ) )>
								<cfif ISNUMERIC( MID(key,12,99) )>
									OR itemname = '#LEFT(TRIM(key),11)#*'
									OR itemname = '#LEFT(TRIM(key),11)#_*'
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 9 ) 
									AND ( listfindnocase( nineString, LEFT(TRIM(key),9) ) ) )>
								<cfif ISNUMERIC( MID(key,10,99) )>
									OR itemname = '#LEFT(TRIM(key),9)#*'
									OR itemname = '#LEFT(TRIM(key),9)#_*'
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 7 ) 
									AND ( listfindnocase( sevenString, LEFT(TRIM(key),7) ) ) )>
								<cfif ISNUMERIC( MID(key,8,99) )>
									OR itemname = '#LEFT(TRIM(key),7)#*'
									OR itemname = '#LEFT(TRIM(key),7)#_*'
								</cfif>
							<cfelseif ((LEN(TRIM(key)) GT 3 ) 
									AND ( listfindnocase( threeString, LEFT(TRIM(key),3) ) ) )>
								<cfif ISNUMERIC( MID(key,4,99) )>
									OR itemname = '#LEFT(TRIM(key),3)#*'
									OR itemname = '#LEFT(TRIM(key),3)#_*'
								</cfif>
							</cfif>
					</cfquery>
					<cfif findMissingParameter.recordCount GT 0>
						<cfset lnMaxLength = findMissingParameter.itemMaxLength />
						<cfswitch expression="#LCASE(findMissingParameter.itemtype)#">
						<cfcase value="ignore"></cfcase>
						<cfcase value="clear">
							<cfset cleanKey = "" />
						</cfcase>
						<cfcase value="boolean">
							<!--- Do not use IsBoolean() here or too many variables will get cleared out needlessly --->
							<cfif NOT listFindNocase( booleanString, cleanKey ) AND LEN(TRIM(cleanKey)) GT 0>
								<cflog file="encodingErrors" text="Cleared boolean #key#=#cleanKey# in #CGI.SCRIPT_NAME#." type="information" application="true" />
								<cfset cleanKey = "" />
							</cfif>
						</cfcase>
						<cfcase value="structure">
							<cfif NOT IsStruct( cleanKey )>
								<cflog file="encodingErrors" text="Cleared structure #key# in #CGI.SCRIPT_NAME#." type="information" application="true" />
								<cfset cleanKey = "" />
							</cfif>
						</cfcase>
						<cfcase value="date,datetime,smalldatetime">
							<cfif NOT ISDATE( cleanKey )>
								<cflog file="encodingErrors" text="Cleared date #key#=#cleanKey# in #CGI.SCRIPT_NAME#." type="information" application="true" />
								<cfset cleanKey = "" />
							</cfif>
						</cfcase>
						<cfcase value="fuseaction"> <!--- This is a special type for the fuseactions; you can remove this if you are not using FuseBox, or adapt it for something else --->
							<cfif len(trim(cleanKey)) GT 0>
								<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[^[a-zA-Z0-9_(.)]]","","all")),lnMaxLength) />
							</cfif>
						</cfcase>
						<cfcase value="string" >
							<cfif len(trim(cleanKey)) GT 0>
								<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[^[:alnum:]]", "", "all")),lnMaxLength) />
							</cfif>
						</cfcase>
						<cfcase value="text,list">
							<cfif len(trim(cleanKey)) GT 0>
								<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							</cfif>
						</cfcase>
						<cfcase value="email">
							<cfif len(trim(cleanKey)) GT 0>
								<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[^(a-zA-Z0-9_\-@!##$%&''+*/=?^{|}.~`)]","","all") ), lnMaxLength ) />
							</cfif>
						</cfcase>
						<cfcase value="numeric,integer">
							<cfif NOT IsNumeric( cleanKey ) AND len(trim(cleanKey)) GT 0>
								<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[^[0-9(.)]]", "", "all")),lnMaxLength) />
							</cfif>
						</cfcase>
						<cfdefaultcase>
							<cflog file="encodingErrors" text="Bad Definition of '#Key#'='#cleanKey#' length=#len(cleankey)# in /CrossScriptDefender.cfc. Update table now!" type="warning" />
							<cfif (LEN(cleankey) GT findMissingParameter.itemmaxlength)
									OR NOT listFindNoCase( cleankey, findMissingParameter.sampleValues, ";" )>
								<cflock timeout="0" throwontimeout="false" type="exclusive">
									<cfquery name="updMissingParameter" datasource="srm" >
										UPDATE [dbo].[CrossScriptDefender] SET
											itemname='#key#'
											<cfif LEN(cleankey) GT findMissingParameter.itemmaxlength>
												, itemmaxlength = #LEN(cleankey)#
											</cfif>
											<cfif NOT listFindNoCase( cleankey, findMissingParameter.sampleValues, ";" )>
												, sampleValues = '#LISTAPPEND(findMissingParameter.sampleValues,"#cleankey#","|")#'
											</cfif>
										WHERE id=#findMissingParameter.id#
									</cfquery>
								</cflock>
							</cfif>
						</cfdefaultcase>
						</cfswitch>
					<cfelse>
						<cfset lnMaxLength = LEN(cleankey) />
						
						<cfif (isValid( "binary", cleanKey ) OR isValid( "boolean", cleanKey )) AND listFindNocase( booleanString, cleanKey )>
							<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							<cfset lnMaxLength = MAX(lnMaxLength,5) />
							<cfset lcItemType = "boolean" />
						<cfelseif isValid( "integer", cleanKey )>
							<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							<cfif listLen(cleanKey) GT 1 AND isValid( "string", cleanKey )>
								<cfset lcItemType="list" />
								<cfset lnMaxLength = MAX(lnMaxLength,20000) />
							<cfelse>
								<cfset lcItemType = "integer" />
							</cfif>
						<cfelseif isValid( "numeric", cleanKey )>
							<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							<cfif listLen(cleanKey) GT 1 AND isValid( "string", cleanKey )>
								<cfset lcItemType="list" />
								<cfset lnMaxLength = MAX(lnMaxLength,20000) />
							<cfelse>
								<cfset lcItemType = "numeric" />
							</cfif>
						<cfelseif isValid( "date", cleanKey )>
							<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							<cfset lnMaxLength = MAX(lnMaxLength,25) />
							<cfset lcItemType = "date" />
						<cfelseif isValid( "email", cleanKey )>
							<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							<cfset lnMaxLength = MAX(lnMaxLength,100) />
							<cfset lcItemType = "email" />
						<cfelseif isValid( "string", cleanKey )>
							<cfset cleanKey = LEFT( TRIM( REREPLACE( cleanKey, "[<]","","all") ), lnMaxLength ) />
							<cfset lcItemType = "text" />
						<cfelseif isValid( "struct", cleanKey )>
							<cfset lnMaxLength = 0 />
							<cfset lcItemType = "struct" />
							<cfset cleanKey = "" />
						<cfelse>
							<cfset cleanKey = "" />
							<cfset lcItemType  = "NULL" />
						</cfif>
						
						<cflog file="encodingErrors" type="warning" 
							text="Missing: '#Key#'='#wasCleanKey#' from /CrossScriptDefender.cfc. Values set to: #lcItemType# len=#lnMaxLength#" />
						
						<cflock timeout="0" throwontimeout="false" type="exclusive">
							<cfquery name="addMissingParameter" datasource="srm" >
								INSERT INTO [dbo].[CrossScriptDefender] ( itemname, itemmaxlength, samplevalues, itemtype )
									VALUES ('#key#', #lnMaxLength#, '#wasCleanKey#',
										<cfif lcItemType EQ "NULL">NULL<cfelse>'#lcItemType#'</cfif> 
									)
							</cfquery>
						</cflock>
						<cfmail from="#emailFrom#" to="#emailTo#" subject="CrossScriptDefender MISSING ITEM" type="html" >
							<p>CrossScriptDefender missing "#key#". See logs and table, update table. User was <cfif LEN(TRIM(cleanKey))>NOT</cfif> stopped from updating.</p>
							<cfdump var="#arguments.scope#" abort="false" />
						</cfmail>
						<cfthrow type="Application" message="Missing Scope Value" 
							detail="CrossScriptDefender missing '#key#'. See logs and table, update table. User was <cfif LEN(TRIM(cleanKey))>NOT</cfif> stopped from updating." /> 	
					</cfif>

					<cfset arguments.scope[key] = cleanKey />

					<cfcatch type="any">
						<!--- Log error, alert programmers, clear key. --->
						<cfmail from="#emailFrom#" to="#emailTo#" subject="CrossScriptDefender CFCATCH" type="html" >
							<p>Error in CrossScriptDefender. Value '#key#' cleared, was '#wasCleanKey#'. If this is a valid item you need to update the table immediately.</p>
							<cfdump var="#arguments#" abort="false" label="arguments" />
							<cfdump var="#cfcatch#"   abort="false" label="cfcatch" />
							<cfdump var="#session#"   abort="false" label="session" expand="false" >
						</cfmail>
						<cflog file="encodingErrors" text="#key# - #cfcatch.Message#" type="error" application="true" />
						<cfset arguments.scope[key] = "" />
					</cfcatch>
				</cftry>
			</cfif>
		</cfloop>
		<cfif beforeAndAfter AND NOT listFindNoCase( ignoreScriptsList, CGI.Script_Name )>
			<cfinvoke method="recordResults" returnVariable="theKey" BAKey="#BAKey#" targetCollection="#arguments.scope#" />
		</cfif>
	</cffunction> 		
	<cffunction name="recordResults" access="public" returntype="String" output="false" 
				description="I attempt to find the difference between the contents of two variables.">
		<cfargument name="BAKey" default="" maxlength="50" type="string" required="false" />
		<cfargument name="targetCollection" type="struct" required="true" />
		
		<cfset VAR tempString = "" />
		<cfset VAR thisCollection = Duplicate( ARGUMENTS.targetCollection ) />
		<cfset VAR strippedStructure="" />
		<cfset VAR strippedCGIStructure="" />

		<cfif NOT IsDefined("ARGUMENTS.BAKey") OR LEN(TRIM(ARGUMENTS.BAKey)) LT 1>
			<cfset ARGUMENTS.BAKey = LEFT( TRIM( CreateUUID() ),50 ) />
		</cfif>
		
		<cfloop collection="#thisCollection#" item="key">
			<cfif IsSimpleValue(thisCollection[key])>
				<cfset cleanKey = canonicalize(thisCollection[key], true, true) />
				<cfset tempString = listAppend( key, cleanKey, "=" ) />
				<cfset strippedStructure = listAppend( strippedStructure, tempString, "|" ) />
			</cfif>
			<cfset tempString = "" />
		</cfloop>
		<cfquery name="findBeforeAfter" datasource="srm" >
			SELECT [id], [before], [after], [cgi], [differences]
				FROM [dbo].[DebugBeforeAfter]
				WHERE [bakey] = '#BAKey#'
		</cfquery>
		<cfif findBeforeAfter.RecordCount GT 0>
			<cfscript>
				oldItems = findBeforeAfter.before; //Items To Delete: 'an,old'
				newItems = findBeforeAfter.after; //Items To Create: 'a,new'
				// ArrayList could be HashSet if items in both lists are expected to be unique
				oldItems = createObject("java", "java.util.ArrayList").init(listToArray(oldItems, ", "));
				newItems = createObject("java", "java.util.ArrayList").init(listToArray(newItems, ", "));
				
				itemsToDelete = createObject("java", "java.util.HashSet").init(oldItems);
				itemsToDelete.removeAll(newItems);
				
				itemsToCreate = createObject("java", "java.util.HashSet").init(newItems);
				itemsToCreate.removeAll(oldItems);
			</cfscript>

			<!--- This needs to be significantly improved! TheDiff is not very accurate --->
			<cfset theDiff = "BEFORE: " & listSort(arrayToList(itemsToDelete.toArray()),"textNoCase") 
				& CHR(13) & "AFTER: " & listSort(arrayToList(itemsToCreate.toArray()),"textNoCase") />

			<cflock timeout="0" throwontimeout="false" type="exclusive">
				<cfquery name="updateBeforeAfter" datasource="srm" >
					<cfset thisID = findBeforeAfter.id />
					UPDATE [dbo].[DebugBeforeAfter] SET
						after = '#strippedStructure#',
						differences = '#theDiff#'
					WHERE id=#thisID#
				</cfquery>
			</cflock>
		<cfelse>
			<!--- The first record updated takes care of CGI as well. --->
			<cfloop collection="#CGI#" item="key">
				<cfif IsSimpleValue(CGI[key])>
					<cfset cleanKey = canonicalize(CGI[key], false, false) /> <!--- If these are set to true, true, you will get a lot of errors! --->
					<cfset tempString = listAppend( key, cleanKey, "=" ) />
					<cfset strippedCGIStructure = listAppend( strippedCGIStructure, tempString, "|" ) />
				</cfif>
				<cfset tempString = "" />
			</cfloop>
			
			<cfif LEN(TRIM(CGI.SCRIPT_NAME)) GT 50>
				<cfset theScript = "..." & RIGHT( TRIM( CGI.SCRIPT_NAME), 47 ) />
			<cfelse>
				<cfset theScript = CGI.SCRIPT_NAME />
			</cfif>

			<cflock timeout="0" throwontimeout="false" type="exclusive">
				<cfquery name="updateBeforeAfter" datasource="srm" >
					INSERT INTO [dbo].[DebugBeforeAfter] ( bakey, servername, scriptname, cgi, before )
						VALUES ( '#BAKey#', '#CGI.SERVER_NAME#', '#theScript#', '#strippedCGIStructure#', '#strippedStructure#' )
				</cfquery>
			</cflock>
		</cfif>
		<cfreturn BAKey />
	</cffunction>
</cfcomponent>