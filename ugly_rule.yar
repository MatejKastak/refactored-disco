import "cuckoo"

rule formatting
{
	meta:
		author = "John Doe, Avast"
		description = "This is a description."
		reason = "Invalid formatting."
		version = 1
	strings:
		$a = "one"
	condition:
		filesize >= 0x1000 and
		#a in (filesize - 0x400 .. filesize) == 2 or
		cuckoo.sync.mutex(/formatting.*/)
}
