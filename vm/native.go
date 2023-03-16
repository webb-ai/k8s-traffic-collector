package vm

var nativeCode string = `
var wrapper = {};


/*
* KFL-based detection, PCAP generation and upload to S3
* =====================================================
* Detect network patterns, represented by KFL queries, export and upload to S3 all L4 
* streams that match the patterns. A Slack message is sent on every new file upoad to S3.
* 
* This is an example for how you run it:

var KFL_PCAP_S3_KFL_ARR =[
    "http and (response.status==500)",
    "dns",
];

function onItemCaptured(data) {
    wrapper.kflPcapS3(data, { 
        kflArr:             KFL_PCAP_S3_KFL_ARR, // Mandory     
    });
}
*/


wrapper.kflPcapS3 = function (data, params) { 
    function kflPcapS3detect(data) {
        wrapper.kflPcapS3Data.kflArr.forEach(function(kflQuery, idx){
            if (kfl.match(kflQuery, data)) {
                wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr.push(data.stream);
                if (wrapper.kflPcapS3Data.verbose) console.log("KFL/PCAP MATCH: KFL=" + 
                    kflQuery + "; PCAP=" + data.stream + "; Idx=" + idx + "; files=" + 
                    wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr.length + "; time: " + wrapper.kflPcapS3Data.pcapInfoArr[idx].time);        
            }
        });
    }
    
    function kflPcapS3Job (){
        console.log(Date().toLocaleString() + ":kflPcapS3Job");
        var now = Date.now();
        
        if ( wrapper.kflPcapS3Data.jobTimePeriod === undefined ||
            now > wrapper.kflPcapS3Data.jobTime + wrapper.kflPcapS3Data.jobTimePeriod){
            wrapper.kflPcapS3Data.jobTime = now;
            wrapper.kflPcapS3Data.pcapInfoArr.forEach(function(pcapInfo, idx){
                if ( (wrapper.kflPcapS3Data.maxL4Streams && 
                        (wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr.length > wrapper.kflPcapS3Data.maxL4Streams))  ||
                    ( (now  >= wrapper.kflPcapS3Data.pcapInfoArr[idx].time + wrapper.kflPcapS3Data.maxMinutesInMS) &&
                        (wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr.length  > 0 ) ) ){
                    wrapper.kflPcapS3Data.pcapInfoArr[idx].time = now;
                    kflPcapS3upload(idx);
                }
            });
        }
        if ( (wrapper.kflPcapS3Data.logUploadTimePeriod === undefined ||
            now > wrapper.kflPcapS3Data.logUploadTime + wrapper.kflPcapS3Data.logUploadTimePeriod) &&
            wrapper.kflPcapS3Data.progressLog.length){
            wrapper.kflPcapS3Data.logUploadTime = now;
            kflPcapS3JobLog();  
        }
    }
    
    function kflPcapS3JobLog (){
        console.log(Date().toLocaleString() + ":kflPcapS3JobLog");
        file.write(wrapper.kflPcapS3Data.progressLogFile,
            JSON.stringify(wrapper.kflPcapS3Data.progressLog));
        if (wrapper.kflPcapS3Data.verbose) console.log("kflPcapS3jobLog|logFile: ", 
            wrapper.kflPcapS3Data.progressLogFile);
        var s3Time = Date.now();
        var location = vendor.s3.put(
            wrapper.kflPcapS3Data.awsRegion,
            wrapper.kflPcapS3Data.awsAccessKeyId,
            wrapper.kflPcapS3Data.awsSecretAccessKey,
            wrapper.kflPcapS3Data.s3Bucket,
            wrapper.kflPcapS3Data.progressLogFile
        ); 
        s3Time = Date.now() - s3Time;
        var msg = "Updated Progress Log: " + location + "; S3 upload time: " + s3Time + "ms";
        if (wrapper.kflPcapS3Data.slackWebhook)
            vendor.slack(
                wrapper.kflPcapS3Data.slackWebhook,
                "Notification", msg,
                "#ff0000"
            );
        if (wrapper.kflPcapS3Data.slackAuthToken && wrapper.kflPcapS3Data.slackChannelId)
            vendor.slackBot(
                wrapper.kflPcapS3Data.slackAuthToken,
                wrapper.kflPcapS3Data.slackChannelId,
                "Notification (kflPcapS3)",
                msg,
                "#ff0000");
        console.log( Date().toLocaleString() + ":" + msg);
    }
    function kflPcapS3upload(idx){
        try{
            var newTempDir = file.mkdirTemp("pcaps3idx" + idx, "");   
            var pcapFilesS3 = wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr;
            wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr = [];
            if (wrapper.kflPcapS3Data.verbose) 
                console.log("pcap.snapshot: " + pcapFilesS3.length + " files");
            var snapshotTime = Date.now();  
            var pcapFile = pcap.snapshot(pcapFilesS3);
            snapshotTime = Date.now() - snapshotTime;
            if (wrapper.kflPcapS3Data.verbose) console.log("pcapFile: ", pcapFile);
            file.move(pcapFile, newTempDir);
            var nameResolutionHistory = pcap.nameResolutionHistory();
            file.write(
                newTempDir + "/name_resolution_history.json",
                JSON.stringify(nameResolutionHistory)
            );
            file.write(
                newTempDir + "/content.json",
                JSON.stringify({
                    pcap_file_name: pcapFile,
                    time: Date().toLocaleString(),
                    kfl_index: idx,
                    kfl_query: wrapper.kflPcapS3Data.pcapInfoArr[idx].kfl,
                    l4_streams: pcapFilesS3
                })
            );
            var tarFile = file.tar(newTempDir);
            var newTarFile = "kfl_" + idx + "_" + tarFile;
            file.move(tarFile, newTarFile);
            if (wrapper.kflPcapS3Data.verbose) console.log("pcapS3Job|tarFile: ", newTarFile);
            var s3Time = Date.now();
            var location = vendor.s3.put(
                wrapper.kflPcapS3Data.awsRegion,
                wrapper.kflPcapS3Data.awsAccessKeyId,
                wrapper.kflPcapS3Data.awsSecretAccessKey,
                wrapper.kflPcapS3Data.s3Bucket,
                newTarFile
            ); 
            s3Time = Date.now() - s3Time;
            file.delete(newTempDir);
            file.delete(newTarFile);   
            var msg = "New PCAP: " + location + "; L4 streams: " + pcapFilesS3.length + 
            "; KFL: \"" + 
            wrapper.kflPcapS3Data.pcapInfoArr[idx].kfl + "\"; Snapshot time: " 
            + snapshotTime + "ms; S3 upload time: " + s3Time + "ms";
            if (wrapper.kflPcapS3Data.slackWebhook)
                vendor.slack(
                    wrapper.kflPcapS3Data.slackWebhook,
                    "Notification", msg,
                    "#ff0000"
                );
            if (wrapper.kflPcapS3Data.slackAuthToken && wrapper.kflPcapS3Data.slackChannelId)
                vendor.slackBot(
                    wrapper.kflPcapS3Data.slackAuthToken,
                    wrapper.kflPcapS3Data.slackChannelId,
                    "Notification (kflPcapS3)",
                    msg,
                    "#ff0000");
            console.log( Date().toLocaleString() + ":" +  msg);  
            wrapper.kflPcapS3Data.progressLog.push({
                file: newTarFile,
                s3_url: location,
                time: Date().toLocaleString(),
                kfl_index: idx,
                kfl_query: wrapper.kflPcapS3Data.pcapInfoArr[idx].kfl,
            });
        }
        catch(err){
            console.error(err);
        }
    }  
    // this is wehere we start
    if (wrapper.hasOwnProperty("kflPcapS3Data") &&
        wrapper.kflPcapS3Data.active !== undefined && 
        !wrapper.kflPcapS3Data.active)
        return;
    if ( !data || (typeof params !== 'object') || !params ){
        console.error("kflPcapS3: Expected data and params. Got: ", JSON.stringify({
            data: data,
            params: params
        }));
        return;       
    }
    if (wrapper.kflPcapS3Data === undefined){ // first and only time
        wrapper.kflPcapS3Data =  {      // set defaults
            kflArr:             [],     // Mandory 
            /* the rest of the properties are optional */
            active:             true,
            verbose:            false,
            slackWebhook:       null,
            slackAuthToken:     null,
            slackAuthChannelId: null,
            maxMinutes:         60,
            maxL4Streams:       100000,
            awsRegion:          env.AWS_REGION,
            awsAccessKeyId:     env.AWS_ACCESS_KEY_ID,
            awsSecretAccessKey: env.AWS_SECRET_ACCESS_KEY,
            s3Bucket:           env.S3_BUCKET,    
            pcapInfoArr:        [],
            firstTime:          true,
            maxMinutesInMS:     3600000,
            progressLogFile:    file.temp("kflPcapS3_log_", "", "json"),
            progressLog:        [],
            logUploadTime:      Date.now(),
            jobTime:            Date.now(),
            logUploadTimePeriod:3600000
        }
        if (params.active !== undefined)
            wrapper.kflPcapS3Data.active = params.active;
        if (!wrapper.kflPcapS3Data.active){
            console.log( Date().toLocaleString() + ":" + "kflPcapS3: Inactive");
            return;
        }
        if (params.kflArr !== undefined)
            wrapper.kflPcapS3Data.kflArr  = params.kflArr;
        else{
            console.error("kflPcapS3: kflArr is mandatory. Got: ", JSON.stringify(params));
            return;       
        }
        if (params.awsRegion !== undefined)
            wrapper.kflPcapS3Data.awsRegion = params.awsRegion;
        if (params.awsAccessKeyId !== undefined)
            wrapper.kflPcapS3Data.awsAccessKeyId = params.awsAccessKeyId;
        if (params.awsAccessKeyId !== undefined)
            wrapper.kflPcapS3Data.awsSecretAccessKey = params.awsSecretAccessKey;
        if (params.s3Bucket !== undefined)
            wrapper.kflPcapS3Data.s3Bucket = params.s3Bucket;     
        if ( (wrapper.kflPcapS3Data.s3Bucket === undefined) ||
            (wrapper.kflPcapS3Data.awsSecretAccessKey === undefined) ||
            (wrapper.kflPcapS3Data.awsRegion === undefined) ){
            console.error("kflPcapS3: One or more of AWS peoprties is missing.");
            return; 
        }    
        if (params.clear === true)
            vendor.s3.clear(
                wrapper.kflPcapS3Data.awsRegion,
                wrapper.kflPcapS3Data.awsAccessKeyId,
                wrapper.kflPcapS3Data.awsSecretAccessKey,
                wrapper.kflPcapS3Data.s3Bucket
            );
        if (params.verbose !== undefined)
            wrapper.kflPcapS3Data.verbose = params.verbose;
        wrapper.kflPcapS3Data.slackWebhook = params.slackWebhook;   
        wrapper.kflPcapS3Data.slackAuthToken = params.slackAuthToken;   
        wrapper.kflPcapS3Data.slackAuthChannelId = params.slackAuthChannelId; 
        if (params.maxMinutes !== undefined)
            wrapper.kflPcapS3Data.maxMinutes = params.maxMinutes;  
        if (params.maxL4Streams !== undefined)
            wrapper.kflPcapS3Data.maxL4Streams = params.maxL4Streams;     
        wrapper.kflPcapS3Data.maxMinutesInMS = wrapper.kflPcapS3Data.maxMinutes * 60000; 
        wrapper.kflPcapS3Data.kflArr.forEach(function(kflQuery, idx){
            wrapper.kflPcapS3Data.pcapInfoArr[idx] = { pcapArr: [], kfl: kflQuery, time: Date.now() };
        });
        jobs.schedule("kfl-pcap-s3", "*/30 * * * * *", kflPcapS3Job);
        //jobs.schedule("kfl-pcap-s3-progress-log", "* */2 * * * *", kflPcapS3JobLog);
    }
    if (wrapper.kflPcapS3Data.active) kflPcapS3detect(data);
}




`
