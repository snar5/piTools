$(document).ready(function () {
	        $("#btnDetails").click(function() {
			netName = document.getElementById('netName').value;
			netChannel = document.getElementById('netChannel').value;
			netEssid = document.getElementById('netEssid').value;
			$("#tbl_status").empty();
			$("#tbl_status").html("<img src='ajax-loader.gif'>loading....");
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
       		 setTimeout(function(){get_details();},5000);
                 $("#tbl_details").empty();
		 if (!results) { 
			$("#loading").show();
			} else { 
				$("#loading").hide();
		 		$("#tbl_details").append("<th><tr><td>Client(s):</td></tr></th>");
                 		$.each(results,function(index,result){
                   		console.log(result.client,result.power);
                   		$("#tbl_details").append("<tr><td height='50' width='150'>Client: <b>" + result.client + "</b> Signal Strength: " + result.power + "</td></tr>");
                        })}
                       } });
        } //End of getwifilist
	

