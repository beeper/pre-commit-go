module example.com/crossmod

go 1.22

require (
	example.com/netlib v0.0.0
	maunium.net/go/mautrix v0.0.0
)

replace (
	example.com/netlib => ../src/example.com/netlib
	maunium.net/go/mautrix => ../src/maunium.net/go/mautrix
)
