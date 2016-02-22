$(document).ready(function () {
	        $("#btnDetails").click(function() {
			netName = document.getElementById('netName').value;
			netChannel = document.getElementById('netChannel').value;
			netEssid = document.getElementById('netEssid').value;
			$("#tbl_status").empty();
			$.ajax({
				type:'POST',
				url: '/captureDetails',
				data:{'essid':netEssid, 'channel':netChannel,'name':netName},
				success:function(results){
					//console.log(results);

					$("#tbl_status").append("<tr><td>Results</td></tr>");
					get_details();
				}


	
				});
					console.log(netName,netChannel,netEssid);
			}); // End btnDetails click
});
 
function get_details(){
        jQuery.ajax({
        type: "POST",
	url: '/apDetail',
        dataType : "json",
        success: function(results){
       		 setTimeout(function(){get_details();},30000);
                 $("#tbl_details").empty();
                 $.each(results,function(index,result){
                   console.log(index,result);
                   var networkname = result.name + "\"," + result.channel + ",\"" + result.essid
                   var networkname = "\"" + networkname + "\"";
                   $("#tbl_details").append("<tr><td height='50' width='150'>SSID:<b>" + result.essid + "</a></b><br>ESSID: " + result.to_from + "</td>i")
                        })
                       } });
        } //End of getwifilist
	

