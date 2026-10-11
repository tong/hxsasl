package sasl;

/**
	Thrown by a mechanism if the server sent invalid data or reported an error.

	The authentication exchange should be aborted.
**/
class Error extends haxe.Exception {}
