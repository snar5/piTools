$(document).ready(function () {	
	
	$("#accordion").accordion({
		collapsible: true,
		active : false,
		activate: function (e, ui){
			$url = $(ui.newHeader[0]).children('a').attr('href');
			$.get($url, function (data) {
				$(ui.newHeader[0]).next().html(data);
			});
		   }
		});
	});
	


function capture(wifiname,channel,essid){
	window.location = "/capture?name=" + wifiname + "&channel=" + channel + "&essid=" + essid;
	}
function get_wifilist(){
	   $.ajax({ 
		type: "POST",
		dataType : "json",      
		success: function(results){
			setTimeout(function(){get_wifilist();},60000);
			$("#accordion").empty();
			$.each(results,function(index,result){
			 console.log(result.power);
			var networkname = result.name + "\"," + result.channel + ",\"" + result.essid
			var networkname = "\"" + networkname + "\"";
			$("accordion").html("<h3>" + result.name + "</h3><div>" + result.essid + "<br>" + result.power + "<br>" + result.channel + "<br>" + result.data + "<br> <button class='btn btn-primary' onclick='capture(" + networkname + ");'>Capture</button></div>");})
			$("#accordion").accordion();
			}
	});
	} //End of getwifilist


