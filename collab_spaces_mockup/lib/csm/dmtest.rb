# A bunch of DataMapper exploration snippets
#
# TODO: turn into real tests

`rm ./collab_spaces.db`
#require 'debug'
require 'pp'
require 'csm/models'

user = CSM::User.create(:name => "sam")
user.emailaddrs << CSM::Emailaddr.create(:name => "addr1")
user.emailaddrs << CSM::Emailaddr.create(:name => "addr2")
user.emailaddrs << CSM::Emailaddr.create(:name => "addr3")
puts '----------------------'
pp user
if user.save && user.emailaddrs.count == 3
  puts "created #{user.class} #{user.name} with #{user.emailaddrs.count} emailaddrs"
else 
  puts "failed to create #{user.class} #{user.name}"
  exit
end
puts '----------------------'

begin
  user = CSM::User.create(:name => "sue")
  addr = CSM::Emailaddr.create(:name => "addr1", :user => user)
  if addr && addr.save && (user.emailaddrs << addr) && user.save
    puts "Good: added duplicate email addr1 to different user"
  else
    puts "Bad: failed to add duplicate email addr1 to different user"
    addr.errors.each { |e| puts e }
    exit
  end
rescue Exception => e
  puts "could not save #{user.class} #{user.name}: #{e}"
  exit
end

begin
  addr = CSM::Emailaddr.create(:name => "addr1", :user => user)
  if addr && addr.save && (user.emailaddrs << addr) && user.save
    puts "Bad: added duplicate email addr1 to same user"
    addr.errors.each { |e| puts e }
    exit
  end
  puts "Good: failed to add duplicate email addr1 to different user"
  addr.errors.each { |e| puts e }
rescue DataObjects::IntegrityError => e
  puts "Good: could not save #{addr.class} #{addr.name}: duplicate email address, #{e.class}"
rescue Exception => e
  puts "Good: could not save #{addr.class} #{addr.name}: #{e.inspect}"
end
  
user.emailaddrs << CSM::Emailaddr.create(:name => "addr5")
user.emailaddrs << CSM::Emailaddr.create(:name => "addr6")
puts '----------------------'
pp user
begin
if user.save then puts "created" else puts "failed" end
rescue Exception => e
  puts "could not save #{user.class} #{user.name}: #{e}"
  exit
end
puts '----------------------'


org = CSM::Org.new
org.name = "acme"
puts '----------------------'
if org.save then puts "created org" else puts "failed org" end
puts '----------------------'

org.projects.create :name => "devops", :description => "the next project"

puts org.projects.count

org.projects.each do |p|
  p.rolemaps.create :name => "developers"
end

org.projects.each do |p| 
  puts p.inspect
  puts p.rolemaps.count
  puts p.rolemaps.inspect 
end



#puts org.methods.inspect

#debugger
# 
# user = CSM::User.create(:name => "joe")
# user = CSM::User.create(:name => "bill")
# 
# puts "-----------------"
# users = CSM::User.all
# puts users.count
# 
# puts "-----------------"
# puts users[1].inspect
# puts "-----------------"
# 
# 
# u = CSM::User.first(:name => "sam")
# #emaddrs = CSM::User.first(:name => "sam").emailaddrs.all
# emaddrs = CSM::User.first(:name => "sam").emailaddrs
# 
# puts emaddrs.inspect

#o = CSM::Org.create(:name => "acme")
#p = o.projects.first(:name => "all")

#p.inspect
