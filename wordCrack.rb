#!/usr/bin/env ruby
# Simple Hasher/Cracker SCript 4 Fun
# MD5, SHA1, Joomla, VB, SMF, & IPB Hash Formats Supported
# By: H.R. & MrGreen
#
# PIC: http://i.imgur.com/tahU35y.jpg
# PIC: http://i.imgur.com/veuNJLm.jpg
# PIC: http://i.imgur.com/2xYjav3.png
 
#ToDo List"
# confirm SMF, IPB, & VB options working as intended (MD5, SHA1, + Joomla already confirmed 100%)
# add Salt File option?

#---------------------''S
require 'digest/md5'
require 'openssl'
require 'optparse'
#---------------------------------->
require 'rubygems'
require 'colorize'
#---------------------''S

#catch all interupts to close down gracefully....
begin
trap("SIGINT") { puts "\n\nWARNING! CTRL+C Detected, Shutting things down and exiting program....".red ; logcleaner(@out) if @found.to_i == 1; exit 666; }
rescue Errno::ENOENT
	exit 666;
end

#print a nice and simple banner when needed
def banner
	if RUBY_PLATFORM =~ /win32/ 
		system('cls')
	else
		system('clear')
	end
	puts
	puts "Simple Wordlist Based Hash Cracker".light_red
	puts "By: ".light_red + "MrGreen".light_green
	puts
	puts "MD5, SHA1, Joomla, VB, SMF, & IPB Hash Formats Supported".light_red
	puts
end

#Generate Various Hashformats using the digest libraries
#0=MD5, 1=SHA1, 2=Joomla, 3=VB, 4=SMF, 5=IPB, 6=ALL Visual Hashes
def generate(num)
	if num.to_i == 0
		@md5 = Digest::MD5.hexdigest(@string)
	elsif num.to_i == 1
		@sha1 = OpenSSL::Digest::SHA1.hexdigest(@string)
	elsif num.to_i == 2
		@saltypass = Digest::MD5.hexdigest("#{@string}" + "#{@salt}")
		@joomla = "#{@saltypass}:#{@salt}"
	elsif num.to_i == 3
		md5 = Digest::MD5.hexdigest(@string)
		@vb = Digest::MD5.hexdigest("#{md5}" + "#{@salt}")
	elsif num.to_i == 4
		@smf = OpenSSL::Digest::SHA1.hexdigest("#{@salt}" + "#{@string}")
	elsif num.to_i == 5
		mdsalt = Digest::MD5.hexdigest(@salt)
		md5 = Digest::MD5.hexdigest(@string)
		@ipb = Digest::MD5.hexdigest("#{mdsalt}" + "#{md5}")
	elsif num.to_i == 6
		@md5 = Digest::MD5.hexdigest(@string)
		@sha1 = OpenSSL::Digest::SHA1.hexdigest(@string)
		@saltypass = Digest::MD5.hexdigest("#{@string}" + "#{@salt}")
		@joomla = "#{@saltypass}:#{@salt}"
	end
end

#RUn comparison test to see if our created hash matches the one provided, indicating a match/crack.etc
#format needs to be specified (md5, sha1, or joomla)
def compare(format)
	if format == 'joomla'
		if @joomla == "#{@hash}:#{@salt}"
			@found=1
			puts "#{@joomla} ".white + "JOOMLA".light_red + ":".white + "#{@string}".light_green
			@catcher << "#{@joomla} JOOMLA:#{@string}"
			@removals << "#{@joomla}"
		end
	elsif format == 'sha1'
		if @sha1 == "#{@hash}"
			@found=1
			puts "#{@sha1} ".white + "SHA1".light_red + ":".white + "#{@string}".light_green
			@catcher << "#{@sha1} SHA1:#{@string}"
			@removals << "#{@sha1}"
		end
	elsif format == 'ipb'
		if @ipb == "#{@hash}"
			@found=1
			puts "#{@hash}:#{@salt} ".white + "IPB".light_red + ":".white + "#{@string}".light_green
			@catcher << "#{@hash}:#{@salt} IPB:#{@string}"
			@removals << "#{@hash}:#{@salt}"
		end
	elsif format == 'smf'
		if @smf == "#{@hash}"
			@found=1
			puts "#{@hash}:#{@salt} ".white + "SMF".light_red + ":".white + "#{@string}".light_green
			@catcher << "#{@hash}:#{@salt} SMF:#{@string}"
			@removals << "#{@hash}:#{@salt}"
		end
	elsif format == 'vb'
		if @vb == "#{@hash}"
			@found=1
			puts "#{@hash}:#{@salt} ".white + "VB".light_red + ":".white + "#{@string}".light_green
			@catcher << "#{@hash}:#{@salt} VB:#{@string}"
			@removals << "#{@hash}:#{@salt}"
		end
	else
		if "#{@md5}" == "#{@hash}"
			@found=1
			puts "#{@md5} ".white + "MD5".light_red + ":".white + "#{@string}".light_green
			@catcher << "#{@md5} MD5:#{@string}"
			@removals << "#{@md5}"
		end
	end
end

#Pass our crackd file to be cleaned of duplicate entries
def logcleaner(file)
	foo = @catcher.uniq
	foo.each do |line|
		clean = File.open("#{@out}", "a+")
		clean.puts line
		clean.close
	end
end

# Pass our Bulk Hashfile here to be cleaned after cracking runs to remove those cracked
def hashcleaner
	puts "Running Hashcleaner".light_green + "............................".white + ">".light_red
	foo=[]
	bar=[]
	foobar=[]
	foo = @hashfile
	foo = foo.uniq #Array of uniq hashes from bulk hash file
	bar = @removals.uniq #array of found hashes
	puts "Uniq Hashes Last Pass".light_red + ": ".cyan + "#{foo.length}".white
	puts "Cracked Hashes Last Pass".light_red + ":".cyan + " #{bar.length}".white
	foo.each do |uncracked|
		bar.each do |cracked|
			if cracked == uncracked
				foobar << "#{cracked}"
			end
		end
	end
	@hashfile = foo - foobar
	count=0
	puts "Remaining Uniq Hashes".light_red + ": ".cyan + "#{@hashfile.length}".white
	puts "Finished Hashcleaner".light_green + "......................".white + ">".light_red
end

###---->
#######--------------->
#################---------------->
##############################-------------------------->
####################################START HERE----------------------------------->
options = {}
optparse = OptionParser.new do |opts| 
	opts.banner = "Usage:".light_red + "#{$0} ".white + "[".light_red + "OPTIONS".white + "]".light_red
	opts.separator ""
	opts.separator "EX:".light_red + " #{$0} -G sup3rs3cr3t".white
	opts.separator "EX:".light_red + " #{$0} -c 5ebe2294ecd0e0f08eab7690d2a6ee69 -F 0 -w /home/hood3drob1n/fun/hashcat/dic/common-dir/10k_most_common.txt".white
	opts.separator "EX:".light_red + " #{$0} -C ~/dumps/demo.hash -F 0 -W /home/hood3drob1n/fun/hashcat/dic/common-dir/".white
	opts.separator "EX:".light_red + " #{$0} --bulk-hash /home/hood3drob1n/pwnd/site3/uncracked.hash -F 1 -w /home/hood3drob1n/fun/hashcat/dic/common-dir/10k_most_common.txt".white
	opts.separator "EX:".light_red + " #{$0} -c f3fc085985c573307e90ca579dbba43c -s ezk4o64enod1r78cry8t29392m3ojy941 -F 2 -w ~/passwords/john.txt".white
	opts.separator "EX:".light_red + " #{$0} -c caef8544a8e65e23f67ab844d4866e8d -s 'uZ*qX' -F 3 -W ~/passwords/".white
	opts.separator "EX:".light_red + " #{$0} -c caef8544a8e65e23f67ab844d4866e8d -s SMFadmin -F 4 -w ~/passwords/john.txt".white
	opts.separator "EX:".light_red + " #{$0} -c f3fc085985c573307e90ca579dbba43c -s ezk4o64enod1r78cry8t29392m3ojy941 -F 2 -W ~/fun/hashcat/wordlists/ -o joomla.cracked".white
	opts.separator ""
	opts.separator "Options: ".light_red
	#setup argument options....
	opts.on('-G', '--generate-hash <STRING>', "\n\tGenerate Hashes for provided String".white) do |genhash|
		options[:method] = 0 #0=>genrate hashes instead of cracking
		@string = genhash.chomp
	end
	opts.on('-c', '--single-hash <HASH>', "\n\tSingle Hash Mode using provided hash".white) do |hash|
		options[:method] = 1 #1 is single, 2 uses Bulk
		@hash = hash.chomp
	end
	opts.on('-C', '--bulk-hash <FILE>', "\n\tBulk Hash for MD5 or SHA1 Mode using provided file".white) do |hashfile|
		options[:method] = 2 #1 is single, 2 uses Bulk
		@hashfileName = hashfile.chomp
		if not File.file?(@hashfileName)
				puts
				puts "Bulk Hash File argument not a file".red + "!".white
				puts "Check arguments or path and try again".red + ".......".white
				puts
				puts opts
				puts
				exit 666;
		end
		# Cut down on file IO and read file into array at start, then we just enumerate array
		hashez=File.open("#{@hashfileName}", 'r').readlines
		@hashfile=[]
		hashez.each do |hashline|
			@hashfile << hashline.chomp
		end
	end
	opts.on('-s', '--salt <SALT>', "\n\tSalt to pair with provided hash for Joomla or VB formats\n\t=> NOTE: username passed isntead of salt if using SMF format".white) do |salty|
		options[:salt] = 1 #0=Disabled, 1=Enabled Single Salt
		@salt = salty.chomp
	end
	opts.on('-F', '--hash-format <NUM>', "\n\tHash Format to try and Crack\n\t0 => MD5    md5(password)\n\t1 => SHA1   sha1(password)\n\t2 => Joomla md5(password.salt)\n\t3 => VB     md5(md5(password).salt)\n\t4 => SMF    sha1(user.password)\n\t5 => IPB    md5(md5(salt).md5(password))".white) do |format|
		options[:format] = format.chomp #0=MD5, 1=SHA1, 2=Joomla
	end
	opts.on('-w', '--wordlist <FILE>', "\n\tWordlist to use for cracking".white) do |wordlist|
		options[:wordlist] = 1 #1=single wordlist, 2=Directory Full of Wordlists
		@wordlist = wordlist.chomp
		if not File.file?(@wordlist)
				puts
				puts "Wordlist argument not a file".red + "!".white
				puts "Check arguments or path and try again".red + ".......".white
				puts
				puts opts
				puts
				exit 666;
		end
	end
	opts.on('-W', '--wordlist-dir <DIR>', "\n\tWordlist Directory to use to find wordlists for cracking".white) do |worddir|
		options[:wordlist] = 2 #1=single wordlist, 2=Directory Full of Wordlists
		@wordir = worddir.chomp
		if not File.directory?(@wordir)
				puts
				puts "Wordlist argument not a Directory".red + "!".white
				puts "Check arguments or path and try again".red + ".......".white
				puts
				puts opts
				puts
				exit 666;
		end
	end
	opts.on('-O', '--out <FILE>', "\n\tFile to store cracked hashes in\n\t=> Defaults to cracked.hashes in current dir if nothing is provided".white) do |output|
		@output = 1
		@out = output.chomp
	end
	opts.on('-h', '--help', "\n\tHelp Menu".white) do 
		banner
		puts opts
		puts
		exit 69
	end
end

begin
	foo = ARGV[0] || ARGV[0] = "-h"
	optparse.parse!
	if options[:method].to_i == 0
		mandatory = [:method]
	else
		mandatory = [:method, :wordlist, :format]
	end
	missing = mandatory.select{ |param| options[param].nil? }
	if not missing.empty?
		puts "Missing or Unknown Options".red + "!".white
		puts optparse
		exit
	end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument
	puts $!.to_s.red
	puts
	puts optparse
	puts
	exit 666;
end

if @output.nil?
	@output = 1
	@out = 'hashes.cracked' #default output file
end

if not options[:salt].to_i == 1
	@salt = (0..32).map{ rand(36).to_s(36) }.join #Generate Salt for Joomla Hashing
end
puts
banner
@found=0
@catcher=[] #Store success in an array to avoid delay in IO file write time, we will write it all after!
@removals=[] #same as above but for removals purposes (no clear text pass here, just hash)
# RUn things based on options set
if options[:method].to_i == 0 #Generate Hashes based on passed String
	puts
	generate(6)
	puts "Plain Text".light_red + ": ".white + "#{@string}".cyan
	puts "MD5".light_red + ": ".cyan + "#{@md5}".white
	puts "SHA1".light_red + ": ".cyan + "#{@sha1}".white
	puts "Joomla".light_red + ": ".cyan + "#{@saltypass}".white + ":".cyan + "#{@salt}".white
	puts "VB, SMF, & IPB Options for cracking only".light_red + "....".white
	puts
elsif options[:method].to_i == 1 #Single Hash Cracking Mode
	puts "Running Single Hash Mode".light_red + "......".white
	while @found.to_i == 0 #Create a loop to keep within until cracked or done.....
		if options[:wordlist].to_i == 1 #Single wordlist mode
			workaround = File.open("#{@wordlist}", 'r').readlines
			workaround = workaround.uniq
			workaround.each do |line|
				@string = line.chomp
				#0=MD5, 1=SHA1, 2=Joomla, 3=VB, 4=SMF, 5=IPB, 6=ALL Visual Hashes
				if options[:format].to_i == 5
					generate(5)
					compare('ipb')
				elsif options[:format].to_i == 4
					generate(4)
					compare('smf')
				elsif options[:format].to_i == 3
					generate(3)
					compare('vb')
				elsif options[:format].to_i == 2
					generate(2)
					compare('joomla')
				elsif options[:format].to_i == 1
					generate(1)
					compare('sha1')
				else
					generate(0)
					compare('md5')
				end
			end
			if @found.to_i == 1
				break
			end
			#Exchausted all search options
			break
		else #Many wordlists
			Dir.foreach("#{@wordir}") do |x|
				if not x == "." and not x == ".."
					if not File.directory?("#{@wordir}/#{x}")
						@wordlist = x.chomp
						puts "Current Wordlist".light_red + ": ".cyan + "#{@wordir}#{@wordlist}".white
						workaround = File.open("#{@wordir}/#{@wordlist}", 'r').readlines
						workaround = workaround.uniq
						workaround.each do |line|
							@string = line.chomp
							if options[:format].to_i == 5
								generate(5)
								compare('ipb')
							elsif options[:format].to_i == 4
								generate(4)
								compare('smf')
							elsif options[:format].to_i == 3
								generate(3)
								compare('vb')
							elsif options[:format].to_i == 2
								generate(2)
								compare('joomla')
							elsif options[:format].to_i == 1
								generate(1)
								compare('sha1')
							else
								generate(0)
								compare('md5')
							end
						end
						if @found.to_i == 1
							break
						end
					end
				end
			end
			#Exchausted all search options
			break
		end
	end
else  #Bulk Hash Cracking Mode
	puts "Running Bulk Hash Mode".light_red + "......".white
	if options[:wordlist].to_i == 1 #Single worlist
		while @hashfile.length > 0
			workaround = File.open("#{@wordlist}", 'r').readlines
			workaround = workaround.uniq
			workaround.each do |line|
				@string = line.chomp
				@hashfile.each do |hashline|
					@hash = hashline.chomp
					if options[:format].to_i == 5
						generate(5)
						compare('ipb')
					elsif options[:format].to_i == 4
						generate(4)
						compare('smf')
					elsif options[:format].to_i == 3
						generate(3)
						compare('vb')
					elsif options[:format].to_i == 2
						generate(2)
						compare('joomla')
					elsif options[:format].to_i == 1
						generate(1)
						compare('sha1')
					else
						generate(0)
						compare('md5')
					end
				end
			end
			if @found.to_i == 1
				hashcleaner
			end
		end
	else
		###########################Multi-Wordlist#######################
		Dir.foreach("#{@wordir}") do |x|
			if not x == "." and not x == ".."
				if not File.directory?("#{@wordir}/#{x}")
					@wordlist = x.chomp
					if @hashfile.length > 0
						puts "Current Wordlist".light_red + ": ".cyan + "#{@wordir}#{@wordlist}".white
						workaround = File.open("#{@wordir}/#{@wordlist}", 'r').readlines
						workaround = workaround.uniq
						workaround.each do |line|
							@string = line.chomp
							@hashfile.each do |hashline|
								@hash = hashline.chomp
								if options[:format].to_i == 5
									generate(5)
									compare('ipb')
								elsif options[:format].to_i == 4
									generate(4)
									compare('smf')
								elsif options[:format].to_i == 3
									generate(3)
									compare('vb')
								elsif options[:format].to_i == 2
									generate(2)
									compare('joomla')
								elsif options[:format].to_i == 1
									generate(1)
									compare('sha1')
								else
									generate(0)
									compare('md5')
								end
							end
						end
						if @found.to_i == 1
							hashcleaner
						end
					else
						puts
						puts "No more hashes remain".light_red + "!".white
					end
				end
			end
		end
	end
end

if @found.to_i == 1
	logcleaner(@out) #clean duplicates from our results file
end

if @output.to_i == 1 and @found.to_i == 1
	puts
	puts "You can find the cracked hashes in the requested outuput file".light_red + ": ".white + "#{@out}".cyan
	puts
	puts "Until next time, Enjoy".light_red + "!".white
	puts
	puts
else
	puts
	puts "Until next time, Enjoy".light_red + "!".white
	puts
	puts
end
#EOF
