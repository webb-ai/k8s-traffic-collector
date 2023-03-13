package vm

var nativeCode string = `
var wrapper = {};

/*
 * KFL-based detection, PCAP generation and upload to S3
 * =====================================================
 * Detect network patterns, represented by KFL queries, export and upload to S3 all L4 
 * streams that match the patterns. A Slack message is sent on every new file upoad to S3.
 * 
 * This is how you run it:

var KFL_PCAP_S3_KFL_ARR =[
    "http and (response.status==500)",
    "dns",
];

function onItemCaptured(data) {
    wrapper.kflPcapS3(data, { 
        kflArr:             KFL_PCAP_S3_KFL_ARR, // Mandory 
        active:             true,
        verbose:            false,
        slackWebhook:       "https://hooks.slack.com/services/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",
        maxMinutes:         60,
        maxL4Streams:       1000,
        awsRegion:          env.AWS_REGION,
        awsAccessKeyId:     env.AWS_ACCESS_KEY_ID,
        awsSecretAccessKey: env.AWS_SECRET_ACCESS_KEY,
        s3Bucket:           env.S3_BUCKET,      
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
    
    function kflPcapS3job (){
        wrapper.kflPcapS3Data.pcapInfoArr.forEach(function(pcapInfo, idx){
            if ( (wrapper.kflPcapS3Data.maxL4Streams && (wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr.length > wrapper.kflPcapS3Data.maxL4Streams))  ||
                (wrapper.kflPcapS3Data.maxL4Streams && ((Date.now() - wrapper.kflPcapS3Data.pcapInfoArr[idx].time) >= wrapper.kflPcapS3Data.maxMinutesInMS)) ){
                kflPcapS3upload(idx);
            }
        });
    }
    function kflPcapS3upload(idx){
        var newTempDir = file.mkdirTemp("pcaps3idx" + idx, "");   
        var pcapFilesS3 = wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr;
        wrapper.kflPcapS3Data.pcapInfoArr[idx].pcapArr = [];
        wrapper.kflPcapS3Data.pcapInfoArr[idx].time = Date.now();
        if (wrapper.kflPcapS3Data.verbose) console.log("pcap.snapshot: " + pcapFilesS3.length + " files");
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
        var tarFile = file.tar(newTempDir);
        if (wrapper.kflPcapS3Data.verbose) console.log("pcapS3Job|tarFile: ", tarFile);
        var s3Time = Date.now();
        var location = vendor.s3.put(
            wrapper.kflPcapS3Data.awsRegion,
            wrapper.kflPcapS3Data.awsAccessKeyId,
            wrapper.kflPcapS3Data.awsSecretAccessKey,
            wrapper.kflPcapS3Data.s3Bucket,
            tarFile
        ); 
        s3Time = Date.now() - s3Time;
        file.delete(newTempDir);
        file.delete(tarFile);   
        if (wrapper.kflPcapS3Data.slackWebhook){
            vendor.slack(
                wrapper.kflPcapS3Data.slackWebhook,
                "New PCAP:",
                location + " containes: " + pcapFilesS3.length + 
                    " L4 streams matching KFL:\"" + 
                    wrapper.kflPcapS3Data.pcapInfoArr[idx].kfl + "\"",
                "#ff0000"
                );
        }
        console.log( location + " containes: " + pcapFilesS3.length + 
            " L4 streams matching KFL:\"" + 
            wrapper.kflPcapS3Data.pcapInfoArr[idx].kfl + "\". Snapshot time: " 
            + snapshotTime + " S3 time: " + s3Time);  
    }

    
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
            maxMinutes:         60,
            maxL4Streams:       100,
            awsRegion:          env.AWS_REGION,
            awsAccessKeyId:     env.AWS_ACCESS_KEY_ID,
            awsSecretAccessKey: env.AWS_SECRET_ACCESS_KEY,
            s3Bucket:           env.S3_BUCKET,    
            pcapInfoArr:        [],
            firstTime:          true,
            maxMinutesInMS:     3600000 
        };
        if (params.active !== undefined)
            wrapper.kflPcapS3Data.active = params.active;
        if (!wrapper.kflPcapS3Data.active){
            console.log("kflPcapS3: Inactive");
            return;
        }
        if (params.kflArr !== undefined)
            wrapper.kflPcapS3Data.kflArr  = params.kflArr;
        else{
            console.error("kflPcapS3: kflArr is mandatory. Got: ", JSON.stringify(params));
            return;       
        }
        if (params.verbose !== undefined)
            wrapper.kflPcapS3Data.verbose = params.verbose;
        if (params.slackWebhook !== undefined)
            wrapper.kflPcapS3Data.slackWebhook = params.slackWebhook;   
        if (params.maxMinutes !== undefined)
            wrapper.kflPcapS3Data.maxMinutes = params.maxMinutes;  
        if (params.maxL4Streams !== undefined)
            wrapper.kflPcapS3Data.maxL4Streams = params.maxL4Streams;
        if (params.awsRegion !== undefined)
            wrapper.kflPcapS3Data.awsRegion = params.awsRegion;
        if (params.awsAccessKeyId !== undefined)
            wrapper.kflPcapS3Data.awsAccessKeyId = params.awsAccessKeyId;
        if (params.awsAccessKeyId !== undefined)
            wrapper.kflPcapS3Data.awsSecretAccessKey = params.awsSecretAccessKey;
        if (params.s3Bucket !== undefined)
            wrapper.kflPcapS3Data.s3Bucket = params.s3Bucket;              
        wrapper.kflPcapS3Data.maxMinutesInMS = wrapper.kflPcapS3Data.maxMinutes * 60 * 1000; 
        wrapper.kflPcapS3Data.kflArr.forEach(function(kflQuery, idx){
            wrapper.kflPcapS3Data.pcapInfoArr[idx] = { pcapArr: [], kfl: kflQuery, time: Date.now() };
        });
        jobs.schedule("kfl-pcap-s3", "*/10 * * * * *", kflPcapS3job);
    }
    if (wrapper.kflPcapS3Data.active) kflPcapS3detect(data);
}
`
