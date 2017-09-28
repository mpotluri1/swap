#
# Cookbook:: swap_file
# Recipe:: default
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

include_recipe 'swap::default'

# Creating the swap_file space . Weblogic demands 500MB of minimum swap_file
#swap_file '/mnt/swap_file' do
#  size 1024
#end

