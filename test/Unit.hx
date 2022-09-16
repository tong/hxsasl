
function main() {
	var runner = new utest.Runner();
	//runner.addCase( new TestPrep() );
	runner.addCase( new TestAnonymousMechanism() );
	runner.addCase( new TestMD5Mechanism() );
	runner.addCase( new TestPlainMechanism() );
	//runner.addCase( new TestSCRAMSHA1Mechanism() );
	utest.ui.Report.create( runner );
	runner.run();
}
