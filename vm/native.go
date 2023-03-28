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
        kflArr:             KFL_PCAP_S3_KFL_ARR, // Mandatory     
    });
}
*/

wrapper.kflPcapS3 = function (data, params) { 
    function kflPcapS3detect(data) {
        wrapper.kflPcapS3Data.kflArr.forEach(function(kflQuery, idx){
            if (kfl.match(kflQuery, data)) {
                wrapper.kflPcapS3Data.pcapArr.push(
                    {pcap: data.stream, kfl: kflQuery, time: Date.now()});
                if (wrapper.kflPcapS3Data.verbose) console.log( Date().toLocaleString() + "| " + 
                    "KFL/PCAP MATCH: KFL=" + 
                    kflQuery + "; PCAP=" + data.stream + "; files=" + 
                    wrapper.kflPcapS3Data.pcapArr.length);        
            }
        });
    }
    
    function kflPcapS3Job(){
        console.log(Date().toLocaleString() + ":kflPcapS3Job");
        var now = Date.now();
        var pcapArr = wrapper.kflPcapS3Data.pcapArr;
        wrapper.kflPcapS3Data.pcapArr = [];
        
        wrapper.kflPcapS3Data.progressLog.current = 
            wrapper.kflPcapS3Data.progressLog.current.concat(pcapArr);
        pcapArr.forEach(function(pcapInfo, idx){
            file.copy(pcap.path(pcapInfo.pcap),wrapper.kflPcapS3Data.pcapFolder + "/" + pcapInfo.pcap); 
        });
        if (wrapper.kflPcapS3Data.verbose) console.log( Date().toLocaleString() + "| " + "Streams copied: " +  pcapArr.length);
        var nameResolutionHistory = pcap.nameResolutionHistory();
        file.write(
            wrapper.kflPcapS3Data.pcapFolder + "/name_resolution_history.json",
            JSON.stringify(nameResolutionHistory)
        );
        file.write(
            wrapper.kflPcapS3Data.pcapFolder + "/content.json",
            JSON.stringify(wrapper.kflPcapS3Data.progressLog.current)
        );
        if (now > wrapper.kflPcapS3Data.lastUpload +  
            wrapper.kflPcapS3Data.maxMinutes*60000){
            var tarFile = file.tar(wrapper.kflPcapS3Data.pcapFolder);
            var location = vendor.s3.put(
                wrapper.kflPcapS3Data.awsRegion,
                wrapper.kflPcapS3Data.awsAccessKeyId,
                wrapper.kflPcapS3Data.awsSecretAccessKey,
                wrapper.kflPcapS3Data.s3Bucket,
                tarFile
            ); 
            file.delete(wrapper.kflPcapS3Data.pcapFolder);
            file.delete(tarFile);   
            wrapper.kflPcapS3Data.progressLog.uploads.push({
                pcaps: pcapArr,
                url:  location,
                time: Date().toLocaleString()
            });
            file.write(
                wrapper.kflPcapS3Data.progressLogFile,
                JSON.stringify(wrapper.kflPcapS3Data.progressLog.uploads)
            );
            location = vendor.s3.put(
                wrapper.kflPcapS3Data.awsRegion,
                wrapper.kflPcapS3Data.awsAccessKeyId,
                wrapper.kflPcapS3Data.awsSecretAccessKey,
                wrapper.kflPcapS3Data.s3Bucket,
                wrapper.kflPcapS3Data.progressLogFile
            ); 
            console.log(Date().toLocaleString() + "| " +  
            "pcapS3Job|S3 TAR uploaded: " + location + 
            "; streams: " + wrapper.kflPcapS3Data.progressLog.current.length);
            
            wrapper.kflPcapS3Data.lastUpload = now;
            file.delete(wrapper.kflPcapS3Data.progressLogFile);
            wrapper.kflPcapS3Data.progressLog.current = [];
            file.mkdir(wrapper.kflPcapS3Data.pcapFolder);
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
            maxMinutes:         60,
            awsRegion:          env.AWS_REGION,
            awsAccessKeyId:     env.AWS_ACCESS_KEY_ID,
            awsSecretAccessKey: env.AWS_SECRET_ACCESS_KEY,
            s3Bucket:           env.S3_BUCKET,    
            pcapArr:            [],
            firstTime:          true,
            progressLogFile:    file.temp("kflPcapS3_log_", "", "json"),
            progressLog:        { uploads: [], current: [] },
            pcapFolder:         "kflPcapS3",
            lastUpload:         Date.now()
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
            console.error("kflPcapS3: One or more of AWS properties is missing.");
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
        if (params.maxMinutes !== undefined)
            wrapper.kflPcapS3Data.maxMinutes = params.maxMinutes;  
        try{
            // check first - TBD
            var tarFile = file.tar(wrapper.kflPcapS3Data.pcapFolder);
            var newTarFile = "abandoned_" + tarFile;
            file.move(tarFile, newTarFile);
            var location = vendor.s3.put(
                wrapper.kflPcapS3Data.awsRegion,
                wrapper.kflPcapS3Data.awsAccessKeyId,
                wrapper.kflPcapS3Data.awsSecretAccessKey,
                wrapper.kflPcapS3Data.s3Bucket,
                newTarFile
            ); 
            file.delete(wrapper.kflPcapS3Data.pcapFolder);
            file.delete(newTarFile);  
            console.log(Date().toLocaleString() + "| " +  
            "pcapS3Job|S3 TAR abandoned: " + location);
            
         } catch(err){
            console.log(Date().toLocaleString() + "|" + "Attempting to upload and clean an old repository", err);
        }
        file.mkdir(wrapper.kflPcapS3Data.pcapFolder);
        jobs.schedule("kfl-pcap-s3", "*/30 * * * * *" , kflPcapS3Job);         
    }
    if (wrapper.kflPcapS3Data.active) kflPcapS3detect(data);
}






`
