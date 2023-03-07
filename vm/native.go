package vm

var nativeCode string = `
var wrapper = {};

wrapper.pcapSnapshot = function(awsRegion, awsAccessKeyId, awsSecretAccessKey, s3Bucket) {
	var dir = file.mkdirTemp("snapshot");

	var snapshot = pcap.snapshot();

	file.move(snapshot, dir);

	var nameResolutionHistory = pcap.nameResolutionHistory();
	file.write(
		dir + "/name_resolution_history.json",
		JSON.stringify(nameResolutionHistory)
	);

	var tarFile = file.tar(dir);

	var location = vendor.s3.put(
		awsRegion,
		awsAccessKeyId,
		awsSecretAccessKey,
		s3Bucket,
		tarFile
	);

	file.delete(dir);
	file.delete(tarFile);

	return location;
}
`
