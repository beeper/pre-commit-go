module example.com/crossmod

go 1.22

require (
	example.com/jobq v0.0.0
	example.com/netlib v0.0.0
	maunium.net/go/mautrix v0.0.0
)

replace (
	example.com/jobq => ../src/example.com/jobq
	example.com/netlib => ../src/example.com/netlib
	maunium.net/go/mautrix => ../src/maunium.net/go/mautrix
)
