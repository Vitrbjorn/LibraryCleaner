LibraryCleanup is a simple python script for cleaning up duplicate files in a library
When run it will ask for a target directory
Once the target directory is given, it will search that folder and all sub folders
For each file it encounters, it will create a hash
Each hash will be compared to a directory of hashes for the directory.
If the hash is not already in the directory, it will be added and the file will not be touched
If the hash is already in the directory, the file will be deleted.
