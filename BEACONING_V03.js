// **************************************************************************************************************************
// Name: Beacon Detection V0.2
// Author: Tom Roeh
// Date: 09/11/2016
//
// Data Structure: {clientip:serverip,[count_of_flows_this_size, Flow.client.bytes]}
//
// **************************************************************************************************************************

var my_app = 'C2';

var my_flows_threshold = 20;

var my_sizes_threshold = 12;

var my_options = {expire: 86400};

var client_subnet_whitelist = ["250.250.250.250/32",
                              ];

// ************************************************************************************************************************** 
//
// DO NOT CHANGE ANYTHING UNDER HERE
//
// **************************************************************************************************************************

// ************************************************************************************************************************** 
//
// HELPER FUNCTIONS
//
// **************************************************************************************************************************

var LZString=function(){function o(o,r){if(!t[o]){t[o]={};for(var n=0;n<o.length;n++)t[o][o.charAt(n)]=n}return t[o][r]}var r=String.fromCharCode,n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$",t={},i={compressToBase64:function(o){if(null==o)return"";var r=i._compress(o,6,function(o){return n.charAt(o)});switch(r.length%4){default:case 0:return r;case 1:return r+"===";case 2:return r+"==";case 3:return r+"="}},decompressFromBase64:function(r){return null==r?"":""==r?null:i._decompress(r.length,32,function(e){return o(n,r.charAt(e))})},compressToUTF16:function(o){return null==o?"":i._compress(o,15,function(o){return r(o+32)})+" "},decompressFromUTF16:function(o){return null==o?"":""==o?null:i._decompress(o.length,16384,function(r){return o.charCodeAt(r)-32})},compressToUint8Array:function(o){for(var r=i.compress(o),n=new Uint8Array(2*r.length),e=0,t=r.length;t>e;e++){var s=r.charCodeAt(e);n[2*e]=s>>>8,n[2*e+1]=s%256}return n},decompressFromUint8Array:function(o){if(null===o||void 0===o)return i.decompress(o);for(var n=new Array(o.length/2),e=0,t=n.length;t>e;e++)n[e]=256*o[2*e]+o[2*e+1];var s=[];return n.forEach(function(o){s.push(r(o))}),i.decompress(s.join(""))},compressToEncodedURIComponent:function(o){return null==o?"":i._compress(o,6,function(o){return e.charAt(o)})},decompressFromEncodedURIComponent:function(r){return null==r?"":""==r?null:(r=r.replace(/ /g,"+"),i._decompress(r.length,32,function(n){return o(e,r.charAt(n))}))},compress:function(o){return i._compress(o,16,function(o){return r(o)})},_compress:function(o,r,n){if(null==o)return"";var e,t,i,s={},p={},u="",c="",a="",l=2,f=3,h=2,d=[],m=0,v=0;for(i=0;i<o.length;i+=1)if(u=o.charAt(i),Object.prototype.hasOwnProperty.call(s,u)||(s[u]=f++,p[u]=!0),c=a+u,Object.prototype.hasOwnProperty.call(s,c))a=c;else{if(Object.prototype.hasOwnProperty.call(p,a)){if(a.charCodeAt(0)<256){for(e=0;h>e;e++)m<<=1,v==r-1?(v=0,d.push(n(m)),m=0):v++;for(t=a.charCodeAt(0),e=0;8>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;h>e;e++)m=m<<1|t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t=0;for(t=a.charCodeAt(0),e=0;16>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}l--,0==l&&(l=Math.pow(2,h),h++),delete p[a]}else for(t=s[a],e=0;h>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;l--,0==l&&(l=Math.pow(2,h),h++),s[c]=f++,a=String(u)}if(""!==a){if(Object.prototype.hasOwnProperty.call(p,a)){if(a.charCodeAt(0)<256){for(e=0;h>e;e++)m<<=1,v==r-1?(v=0,d.push(n(m)),m=0):v++;for(t=a.charCodeAt(0),e=0;8>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;h>e;e++)m=m<<1|t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t=0;for(t=a.charCodeAt(0),e=0;16>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}l--,0==l&&(l=Math.pow(2,h),h++),delete p[a]}else for(t=s[a],e=0;h>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;l--,0==l&&(l=Math.pow(2,h),h++)}for(t=2,e=0;h>e;e++)m=m<<1|1&t,v==r-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;for(;;){if(m<<=1,v==r-1){d.push(n(m));break}v++}return d.join("")},decompress:function(o){return null==o?"":""==o?null:i._decompress(o.length,32768,function(r){return o.charCodeAt(r)})},_decompress:function(o,n,e){var t,i,s,p,u,c,a,l,f=[],h=4,d=4,m=3,v="",w=[],A={val:e(0),position:n,index:1};for(i=0;3>i;i+=1)f[i]=i;for(p=0,c=Math.pow(2,2),a=1;a!=c;)u=A.val&A.position,A.position>>=1,0==A.position&&(A.position=n,A.val=e(A.index++)),p|=(u>0?1:0)*a,a<<=1;switch(t=p){case 0:for(p=0,c=Math.pow(2,8),a=1;a!=c;)u=A.val&A.position,A.position>>=1,0==A.position&&(A.position=n,A.val=e(A.index++)),p|=(u>0?1:0)*a,a<<=1;l=r(p);break;case 1:for(p=0,c=Math.pow(2,16),a=1;a!=c;)u=A.val&A.position,A.position>>=1,0==A.position&&(A.position=n,A.val=e(A.index++)),p|=(u>0?1:0)*a,a<<=1;l=r(p);break;case 2:return""}for(f[3]=l,s=l,w.push(l);;){if(A.index>o)return"";for(p=0,c=Math.pow(2,m),a=1;a!=c;)u=A.val&A.position,A.position>>=1,0==A.position&&(A.position=n,A.val=e(A.index++)),p|=(u>0?1:0)*a,a<<=1;switch(l=p){case 0:for(p=0,c=Math.pow(2,8),a=1;a!=c;)u=A.val&A.position,A.position>>=1,0==A.position&&(A.position=n,A.val=e(A.index++)),p|=(u>0?1:0)*a,a<<=1;f[d++]=r(p),l=d-1,h--;break;case 1:for(p=0,c=Math.pow(2,16),a=1;a!=c;)u=A.val&A.position,A.position>>=1,0==A.position&&(A.position=n,A.val=e(A.index++)),p|=(u>0?1:0)*a,a<<=1;f[d++]=r(p),l=d-1,h--;break;case 2:return w.join("")}if(0==h&&(h=Math.pow(2,m),m++),f[l])v=f[l];else{if(l!==d)return null;v=s+s.charAt(0)}w.push(v),f[d++]=s+v.charAt(0),h--,s=v,0==h&&(h=Math.pow(2,m),m++)}}};return i}();"function"==typeof define&&define.amd?define(function(){return LZString}):"undefined"!=typeof module&&null!=module&&(module.exports=LZString);

var ip2long = function(ip) {
    
   var components;

   if (components = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)) {
    
       var iplong = 0;
       var power  = 1;
       for(var i=4; i>=1; i-=1) {
           iplong += power * parseInt(components[i]);
           power  *= 256;
       }
       return iplong;
   }
   else return -1;
};

var inSubNet = function(ip, subnet) {   
   
   var mask, base_ip, long_ip = ip2long(ip);
   
   if ((mask = subnet.match(/^(.*?)\/(\d{1,2})$/)) && ((base_ip=ip2long(mask[1])) >= 0) ) {
       var freedom = Math.pow(2, 32 - parseInt(mask[2]));
       return (long_ip > base_ip) && (long_ip < base_ip + freedom - 1);
   }
   else return false;
};

// ************************************************************************************************************************** 
//
// MAIN PROGRAM
//
// **************************************************************************************************************************

var my_key = String(Flow.client.ipaddr + ':' + Flow.server.ipaddr);
var my_flow = Session.lookup(my_key);

var clientip_obj = Flow.client.ipaddr;
var clientip_str = String(clientip_obj);
var serverip_obj = Flow.server.ipaddr;  
var serverip_str = String(serverip_obj);


for (j = 0; j < client_subnet_whitelist.length; j++) {

    if (inSubNet(clientip_str, client_subnet_whitelist[j]) == true) {

        if (inSubNet(serverip_str, client_subnet_whitelist[j]) == false) {

            if (my_flow) {
                my_flow = JSON.parse(LZString.decompressFromBase64(my_flow));
                for (i = 0; i < my_flow.length; i++) {
                    if (my_flow[i][1] == Flow.client.bytes) {
                        my_flow[i][0] =  my_flow[i][0] + 1;
                        Session.replace(my_key, LZString.compressToBase64(JSON.stringify(my_flow)));  
                        if (my_flow[i][0] > my_flows_threshold) {
                            debug('WARNING: Caught a possible infected device for ' + my_key + ' with values ' + JSON.stringify(my_flow));
                            Application(my_app).metricAddCount('beaconing-device-count', 1);
                            Application(my_app).metricAddDetailCount('beaconing-device-count-detail', Flow.client.ipaddr, 1);
                            Session.remove(my_key);                                                  
                        }               
                        return;         
                    }         
                    else {
                        no_match = true;
                    }
                }   
    
                if (no_match) {
                    my_flow.push([1, Flow.client.bytes]);
                    Session.replace(my_key, LZString.compressToBase64(JSON.stringify(my_flow))); 
                }        
    
                if (my_flow.length > my_sizes_threshold) {
                    debug('INFO: Removing entry for ' + my_key + ' due to excessive flow size variety with ' + JSON.stringify(my_flow));
                    Session.remove(my_key);       
                }
            }

            else {
                my_flow = [];
                my_flow.push([1, Flow.client.bytes]);
                Session.replace(my_key, LZString.compressToBase64(JSON.stringify(my_flow)));
            }                               
        }
    }
}

