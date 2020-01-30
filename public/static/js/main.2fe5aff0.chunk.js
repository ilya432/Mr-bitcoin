(this.webpackJsonpfront=this.webpackJsonpfront||[]).push([[0],{109:function(e,t){},130:function(e,t,n){},131:function(e,t,n){},132:function(e,t,n){},133:function(e,t,n){},134:function(e,t,n){},135:function(e,t,n){},136:function(e,t,n){},138:function(e,t,n){"use strict";n.r(t);var a,c=n(0),r=n.n(c),o=n(27),s=n.n(o),i=n(15),l=(n(79),n(4)),u=n(11),m=Object(u.a)(),p=(n(80),n(3)),d=n(20),g=n(29),f=n(5),h=n(6),v=n(8),b=n(7),A=n(9),w=n(65),C=n.n(w),E={setup:function(){a=C()("/")},terminate:function(){a=null},on:function(e,t){a.on(e,t)},off:function(e,t){a.off(e,t)},emit:function(e,t){a.emit(e,t)}};var y=function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).state={msg:{from:"Me",txt:""},msgs:[],topic:"Love"},n.addMsg=function(e){n.setState((function(t){return{msgs:[].concat(Object(g.a)(t.msgs),[e])}}))},n.changeTopic=function(){E.emit("chat topic",n.state.topic)},n.sendMsg=function(e){e.preventDefault(),E.emit("chat newMsg",n.state.msg.txt),n.setState({msg:{from:"Me",txt:""}})},n.handleChange=function(e){var t=e.target,a=t.name,c=t.value;n.setState(Object(d.a)({},a,c),(function(){return n.changeTopic(c)}))},n.msgHandleChange=function(e){var t=e.target,a=t.name,c=t.value;n.setState((function(e){return{msg:Object(p.a)({},e.msg,Object(d.a)({},a,c))}}))},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"componentDidMount",value:function(){E.setup(),E.emit("chat topic",this.state.topic),E.on("chat addMsg",this.addMsg)}},{key:"componentWillUnmount",value:function(){E.off("chat addMsg",this.addMsg),E.terminate()}},{key:"render",value:function(){return r.a.createElement("div",{className:"about"},r.a.createElement("h1",null,"About Us"),r.a.createElement("p",null,"We like You"),r.a.createElement("h2",null,"Lets Chat About ",this.state.topic),r.a.createElement("div",null,r.a.createElement("label",null,r.a.createElement("input",{type:"radio",name:"topic",value:"Love",checked:"Love"===this.state.topic,onChange:this.handleChange}),"Love"),r.a.createElement("label",null,r.a.createElement("input",{type:"radio",name:"topic",value:"Politics",checked:"Politics"===this.state.topic,onChange:this.handleChange}),"Politics")),r.a.createElement("form",{onSubmit:this.sendMsg},r.a.createElement("input",{type:"text",value:this.state.msg.txt,onChange:this.msgHandleChange,name:"txt"}),r.a.createElement("button",null,"Send")),r.a.createElement("ul",null,this.state.msgs.map((function(e,t){return r.a.createElement("li",{key:t},e)}))))}}]),t}(c.Component),O=n(1),x=n.n(O),S=n(22),U=n.n(S),j=U.a.create({withCredentials:!0}),N=function(e,t){return _(e,"GET",t)},k=function(e,t){return _(e,"POST",t)},T=function(e,t){return _(e,"PUT",t)},D=function(e,t){return _(e,"DELETE",t)};function _(e){var t,n,a,c=arguments;return x.a.async((function(r){for(;;)switch(r.prev=r.next){case 0:return t=c.length>1&&void 0!==c[1]?c[1]:"get",n=c.length>2&&void 0!==c[2]?c[2]:null,c.length>3?c[3]:void 0,r.prev=3,r.next=6,x.a.awrap(j({url:"".concat("/api/").concat(e),method:t,data:n}));case 6:return a=r.sent,r.abrupt("return",a.data);case 10:throw r.prev=10,r.t0=r.catch(3),console.log("Had Issues ".concat(t,"ing to the backend, endpoint: ").concat(e,", with data: ").concat(n)),console.dir(r.t0),r.t0.response&&401===r.t0.response.status&&m.push("/"),r.t0;case 16:case"end":return r.stop()}}),null,null,[[3,10]])}var I={login:function(e){var t;return x.a.async((function(n){for(;;)switch(n.prev=n.next){case 0:return n.next=2,x.a.awrap(k("auth/login",e));case 2:return t=n.sent,n.abrupt("return",L(t));case 4:case"end":return n.stop()}}))},logout:function(){return x.a.async((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,x.a.awrap(k("auth/logout"));case 2:sessionStorage.clear();case 3:case"end":return e.stop()}}))},signup:function(e){var t;return x.a.async((function(n){for(;;)switch(n.prev=n.next){case 0:return n.next=2,x.a.awrap(k("auth/signup",e));case 2:return t=n.sent,n.abrupt("return",L(t));case 4:case"end":return n.stop()}}))},getUsers:function(){return N("user")},getById:function(e){return N("user/".concat(e))},remove:function(e){return D("user/".concat(e))},update:function(e){return T("user/".concat(e._id),e)}};function L(e){return sessionStorage.setItem("user",JSON.stringify(e)),e}function B(){return function(e){var t;return x.a.async((function(n){for(;;)switch(n.prev=n.next){case 0:return n.prev=0,e({type:"LOADING_START"}),n.next=4,x.a.awrap(I.getUsers());case 4:t=n.sent,e(M(t)),n.next=11;break;case 8:n.prev=8,n.t0=n.catch(0),console.log("UserActions: err in loadUsers",n.t0);case 11:return n.prev=11,e({type:"LOADING_DONE"}),n.finish(11);case 14:case"end":return n.stop()}}),null,null,[[0,8,11,14]])}}function P(e){return{type:"SET_USER",user:e}}function M(e){return{type:"SET_USERS",users:e}}function z(e){return{type:"USER_REMOVE",userId:e}}var q=function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).state={msg:"",loginCred:{email:"",password:""},signupCred:{email:"",password:"",username:"",amount:""}},n.loginHandleChange=function(e){var t=e.target,a=t.name,c=t.value;n.setState((function(e){return{loginCred:Object(p.a)({},e.loginCred,Object(d.a)({},a,c))}}))},n.signupHandleChange=function(e){var t=e.target,a=t.name,c=t.value;n.setState((function(e){return{signupCred:Object(p.a)({},e.signupCred,Object(d.a)({},a,c))}}))},n.doLogin=function(e){var t,a,c,r;return x.a.async((function(o){for(;;)switch(o.prev=o.next){case 0:if(e.preventDefault(),t=n.state.loginCred,a=t.email,c=t.password,a&&c){o.next=4;break}return o.abrupt("return",n.setState({msg:"Please enter user/password"}));case 4:r={email:a,password:c},n.props.login(r),n.setState({loginCred:{email:"",password:""}});case 7:case"end":return o.stop()}}))},n.doSignup=function(e){var t,a,c,r,o,s;return x.a.async((function(i){for(;;)switch(i.prev=i.next){case 0:if(e.preventDefault(),t=n.state.signupCred,a=t.email,c=t.password,r=t.username,o=t.amount,a&&c&&r&&o){i.next=4;break}return i.abrupt("return",n.setState({msg:"All inputs are required!"}));case 4:s={email:a,password:c,username:r,amount:o},n.props.signup(s),n.setState({signupCred:{email:"",password:"",username:"",amount:""}});case 7:case"end":return i.stop()}}))},n.removeUser=function(e){n.props.removeUser(e)},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"render",value:function(){var e=r.a.createElement("form",{onSubmit:this.doSignup},r.a.createElement("input",{type:"text",name:"email",value:this.state.signupCred.email,onChange:this.signupHandleChange,placeholder:"Email"}),r.a.createElement("br",null),r.a.createElement("input",{name:"password",type:"password",value:this.state.signupCred.password,onChange:this.signupHandleChange,placeholder:"Password"}),r.a.createElement("br",null),r.a.createElement("input",{type:"text",name:"username",value:this.state.signupCred.username,onChange:this.signupHandleChange,placeholder:"Username"}),r.a.createElement("br",null),r.a.createElement("input",{type:"text",name:"amount",value:this.state.signupCred.amount,onChange:this.signupHandleChange,placeholder:"Amount"}),r.a.createElement("br",null),r.a.createElement("button",null,"Signup")),t=r.a.createElement("form",{onSubmit:this.doLogin},r.a.createElement("input",{type:"text",name:"email",value:this.state.loginCred.email,onChange:this.loginHandleChange,placeholder:"Email"}),r.a.createElement("br",null),r.a.createElement("input",{type:"password",name:"password",value:this.state.loginCred.password,onChange:this.loginHandleChange,placeholder:"Password"}),r.a.createElement("br",null),r.a.createElement("button",null,"Login")),n=this.props.loggedInUser;return r.a.createElement("div",{className:"test"},r.a.createElement("h2",null,this.state.msg),n&&r.a.createElement("div",null,r.a.createElement("h2",null,"Welcome: ",n.username," "),r.a.createElement("button",{onClick:this.props.logout},"Logout")),!n&&t,!n&&e)}}]),t}(c.Component),H={login:function(e){return function(t){var n;return x.a.async((function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,x.a.awrap(I.login(e));case 2:n=a.sent,t(P(n));case 4:case"end":return a.stop()}}))}},logout:function(){return function(e){return x.a.async((function(t){for(;;)switch(t.prev=t.next){case 0:return t.next=2,x.a.awrap(I.logout());case 2:e(P(null));case 3:case"end":return t.stop()}}))}},signup:function(e){return function(t){var n;return x.a.async((function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,x.a.awrap(I.signup(e));case 2:n=a.sent,t(P(n));case 4:case"end":return a.stop()}}))}},removeUser:function(e){return function(t){return x.a.async((function(n){for(;;)switch(n.prev=n.next){case 0:return n.prev=0,n.next=3,x.a.awrap(I.remove(e));case 3:t(z(e)),n.next=9;break;case 6:n.prev=6,n.t0=n.catch(0),console.log("UserActions: err in removeUser",n.t0);case 9:case"end":return n.stop()}}),null,null,[[0,6]])}},loadUsers:B},R=Object(i.b)((function(e){return{users:e.user.users,loggedInUser:e.user.loggedInUser,isLoading:e.system.isLoading}}),H)(q),Q=(n(130),n(39)),G=n.n(Q),X={getRate:function(e){var t;return x.a.async((function(n){for(;;)switch(n.prev=n.next){case 0:return n.prev=0,n.next=3,x.a.awrap(U.a.get("https://blockchain.info/tobtc?currency=".concat(e.symbol,"&value=").concat(e.amount)));case 3:return t=n.sent,n.abrupt("return",t.data);case 7:throw n.prev=7,n.t0=n.catch(0),console.log("Had Issues getting bitcoin rate-  ".concat(n.t0)),console.dir(n.t0),n.t0.response&&401===n.t0.response.status&&m.push("/"),n.t0;case 13:case"end":return n.stop()}}),null,null,[[0,7]])},getMarketPrice:function(e){return x.a.async((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,x.a.awrap(U()());case 2:e.sent;case 3:case"end":return e.stop()}}))}};function K(e){return{type:"SET_RATE",rate:e}}var V=function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).state={},n.toContacts=function(){n.props.history.push("/contacts/")},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"componentDidMount",value:function(){this.props.loadUsers(),this.props.getRate({symbol:"USD",amount:1})}},{key:"render",value:function(){var e=this.props,t=e.users,n=e.loggedInUser,a=e.rate;return r.a.createElement("div",{className:"home flex"},t&&n&&r.a.createElement("div",{className:"user-info-container flex row"},r.a.createElement("div",{className:" flex col"},r.a.createElement("span",{className:"user-name-field"},"Hello ",n.username),r.a.createElement("div",{className:"user-amount-container flex row"},r.a.createElement("span",{className:"user-amount-field"},n.amount),r.a.createElement("img",{className:"bitcoin-small-img",alt:"bitcoin",src:G.a})),r.a.createElement("div",{className:"bitcoin-rate-container flex row"},r.a.createElement("span",{className:"bitcoin-rate"},a),r.a.createElement("img",{className:"bitcoin-small-img",alt:"bitcoin",src:G.a}))),r.a.createElement("button",{className:"contacts-btn",onClick:this.toContacts},"Contacts")),t&&!n&&r.a.createElement("div",{className:"guest-login"},r.a.createElement("span",{className:"guest-login-msg"},"Please login")))}}]),t}(c.Component),Y={loadUsers:B,getRate:function(e){return function(t){var n;return x.a.async((function(a){for(;;)switch(a.prev=a.next){case 0:return a.prev=0,a.next=3,x.a.awrap(X.getRate(e));case 3:n=a.sent,t(K(n)),a.next=10;break;case 7:a.prev=7,a.t0=a.catch(0),console.log("ContactActions: err in loadContacts",a.t0);case 10:case"end":return a.stop()}}),null,null,[[0,7]])}}},F=Object(i.b)((function(e){return{users:e.user.users,loggedInUser:e.user.loggedInUser,rate:e.bitcoin.rate}}),Y)(V),J=(n(131),{getContacts:function(e){return new Promise((function(t){var n,a=W;e&&e.term&&(n=(n=e.term).toLocaleLowerCase(),a=W.filter((function(e){return e.name.toLocaleLowerCase().includes(n)||e.phone.toLocaleLowerCase().includes(n)||e.email.toLocaleLowerCase().includes(n)}))),t(a.sort((function(e,t){return e.name.toLocaleLowerCase()<t.name.toLocaleLowerCase()?-1:e.name.toLocaleLowerCase()>t.name.toLocaleLowerCase()?1:0})))}))},getContactById:function(e){return new Promise((function(t,n){var a=W.find((function(t){return t._id===e}));a?t(a):n("Contact id ".concat(e," not found!"))}))},deleteContact:function(e){return new Promise((function(t,n){var a=W.findIndex((function(t){return t._id===e}));-1!==a&&W.splice(a,1),t(W)}))},saveContact:function(e){return e._id?function(e){return new Promise((function(t,n){var a=W.findIndex((function(t){return e._id===t._id}));-1!==a&&(W[a]=e),t(e)}))}(e):function(e){return new Promise((function(t,n){e._id=function(){for(var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:10,t="",n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",a=0;a<e;a++)t+=n.charAt(Math.floor(Math.random()*n.length));return t}(),W.push(e),t(e)}))}(e)},getEmptyContact:function(){return{name:"",email:"",phone:""}}}),W=[{_id:"5a56640269f443a5d64b32ca",name:"Ochoa Hyde",email:"ochoahyde@renovize.com",phone:"+1 (968) 593-3824",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a5664025f6ae9aa24a99fde",name:"Hallie Mclean",email:"halliemclean@renovize.com",phone:"+1 (948) 464-2888",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a56640252d6acddd183d319",name:"Parsons Norris",email:"parsonsnorris@renovize.com",phone:"+1 (958) 502-3495",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a566402ed1cf349f0b47b4d",name:"Rachel Lowe",email:"rachellowe@renovize.com",phone:"+1 (911) 475-2312",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a566402abce24c6bfe4699d",name:"Dominique Soto",email:"dominiquesoto@renovize.com",phone:"+1 (807) 551-3258",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a566402a6499c1d4da9220a",name:"Shana Pope",email:"shanapope@renovize.com",phone:"+1 (970) 527-3082",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a566402f90ae30e97f990db",name:"Faulkner Flores",email:"faulknerflores@renovize.com",phone:"+1 (952) 501-2678",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a5664027bae84ef280ffbdf",name:"Holder Bean",email:"holderbean@renovize.com",phone:"+1 (989) 503-2663",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a566402e3b846c5f6aec652",name:"Rosanne Shelton",email:"rosanneshelton@renovize.com",phone:"+1 (968) 454-3851",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a56640272c7dcdf59c3d411",name:"Pamela Nolan",email:"pamelanolan@renovize.com",phone:"+1 (986) 545-2166",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a5664029a8dd82a6178b15f",name:"Roy Cantu",email:"roycantu@renovize.com",phone:"+1 (929) 571-2295",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a5664028c096d08eeb13a8a",name:"Ollie Christian",email:"olliechristian@renovize.com",phone:"+1 (977) 419-3550",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a5664026c53582bb9ebe9d1",name:"Nguyen Walls",email:"nguyenwalls@renovize.com",phone:"+1 (963) 471-3181",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a56640298ab77236845b82b",name:"Glenna Santana",email:"glennasantana@renovize.com",phone:"+1 (860) 467-2376",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a56640208fba3e8ecb97305",name:"Malone Clark",email:"maloneclark@renovize.com",phone:"+1 (818) 565-2557",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a566402abb3146207bc4ec5",name:"Floyd Rutledge",email:"floydrutledge@renovize.com",phone:"+1 (807) 597-3629",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a56640298500fead8cb1ee5",name:"Grace James",email:"gracejames@renovize.com",phone:"+1 (959) 525-2529",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a56640243427b8f8445231e",name:"Tanner Gates",email:"tannergates@renovize.com",phone:"+1 (978) 591-2291",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"},{_id:"5a5664025c3abdad6f5e098c",name:"Lilly Conner",email:"lillyconner@renovize.com",phone:"+1 (842) 587-3812",imgUrl:"https://res.cloudinary.com/ilya432/image/upload/v1580253973/contact_wmvcwb.png"}];function Z(e){return function(t){var n;return x.a.async((function(a){for(;;)switch(a.prev=a.next){case 0:return a.prev=0,a.next=3,x.a.awrap(J.getContactById(e));case 3:n=a.sent,t(ee(n)),a.next=10;break;case 7:a.prev=7,a.t0=a.catch(0),console.log("ContactActions: err in loadContact",a.t0);case 10:case"end":return a.stop()}}),null,null,[[0,7]])}}function $(e){return{type:"SET_CONTACTS",contacts:e}}function ee(e){return{type:"SET_SELECTED_CONTACT",contact:e}}n(132);var te=function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).state={filterBy:{term:""}},n.onFilterBy=function(e){var t=e.target.value;""===t?n.props.filterContacts():n.setState({filterBy:{term:t}},(function(){return n.props.filterContacts(n.state.filterBy)})),console.log("this.state.filterBy: ",n.state.filterBy.term)},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"render",value:function(){return r.a.createElement("input",{className:"search-input",type:"text",name:"term",placeholder:"find...",onChange:this.onFilterBy,onKeyDown:this.onFilterBy})}}]),t}(c.Component),ne=(n(133),function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).onSelectContact=function(e){n.props.onSelectContact&&n.props.onSelectContact(e)},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"render",value:function(){var e=this,t=this.props.contact;return r.a.createElement("li",{className:"contact-list-item flex row",onClick:function(){return e.onSelectContact(t.Id)}},r.a.createElement("img",{className:"contact-img",alt:"contact pic",src:t.imgUrl}),r.a.createElement("h2",{className:"contact-name"},t.name))}}]),t}(c.Component)),ae=(n(134),function(e){function t(){return Object(f.a)(this,t),Object(v.a)(this,Object(b.a)(t).apply(this,arguments))}return Object(A.a)(t,e),Object(h.a)(t,[{key:"render",value:function(){var e=this.props,t=e.contacts,n=e.onSelectContact;return r.a.createElement("div",{className:"contact-list-container flex"},r.a.createElement("ul",{className:"contact-list"},t.map((function(e){return r.a.createElement(ne,{key:e._id,contact:e,onSelectContact:function(){return n(e._id)}})}))))}}]),t}(c.Component)),ce=function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).state={selectedContact:{name:""}},n.filterContacts=function(e){e?n.props.loadContacts(e):n.props.loadContacts()},n.onSelectContact=function(e){n.props.loadSelectedContact(e).then((function(){n.props.history.push("/contact/".concat(n.props.selectedContact._id))}))},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"componentDidMount",value:function(){this.props.loadContacts(),this.props.loadUsers()}},{key:"render",value:function(){var e=this.props.contacts;return r.a.createElement("section",{className:"contacts-page-container"},r.a.createElement("h2",null,"Contacts"),r.a.createElement(te,{filterContacts:this.filterContacts}),r.a.createElement(ae,{contacts:e,onSelectContact:this.onSelectContact}))}}]),t}(c.Component),re={loadUsers:B,loadContacts:function(e){return function(t){var n;return x.a.async((function(a){for(;;)switch(a.prev=a.next){case 0:return a.prev=0,a.next=3,x.a.awrap(J.getContacts(e));case 3:n=a.sent,t($(n)),a.next=10;break;case 7:a.prev=7,a.t0=a.catch(0),console.log("ContactActions: err in loadContacts",a.t0);case 10:case"end":return a.stop()}}),null,null,[[0,7]])}},loadSelectedContact:Z},oe=Object(i.b)((function(e){return{users:e.user.users,loggedInUser:e.user.loggedInUser,contacts:e.contact.contacts,selectedContact:e.contact.selectedContact}}),re)(ce),se=(n(135),function(e){function t(){var e,n;Object(f.a)(this,t);for(var a=arguments.length,c=new Array(a),r=0;r<a;r++)c[r]=arguments[r];return(n=Object(v.a)(this,(e=Object(b.a)(t)).call.apply(e,[this].concat(c)))).state={},n}return Object(A.a)(t,e),Object(h.a)(t,[{key:"componentDidMount",value:function(){this.props.loadUsers()}},{key:"render",value:function(){var e=this.props.selectedContact;return r.a.createElement("div",{className:"contact-details-container flex col"},r.a.createElement("span",{className:"contact-info-txt contact-name"},e.name),r.a.createElement("span",{className:"contact-info-txt contact-mail"},e.email),r.a.createElement("span",{className:"contact-info-txt contact-phone"},e.phone),r.a.createElement("img",{className:"contact-info-img",src:e.imgUrl}))}}]),t}(c.Component)),ie={loadUsers:B,loadSelectedContact:Z},le=Object(i.b)((function(e){return{users:e.user.users,loggedInUser:e.user.loggedInUser,selectedContact:e.contact.selectedContact}}),ie)(se),ue=n(30),me=n(66),pe=n.n(me),de=n(67),ge=n.n(de);n(136);var fe=Object(l.f)((function(){return r.a.createElement("nav",{className:"nav flex row"},r.a.createElement("div",{className:"nav-container flex row"},r.a.createElement("div",{className:"logo-container nav-item flex row"},r.a.createElement(ue.a,{className:"nav-link",to:"/"},r.a.createElement("img",{className:"Logo-img",alt:"Logo",src:pe.a})),r.a.createElement(ue.a,{className:"nav-link",to:"/"},r.a.createElement("span",{className:"logo-text"},r.a.createElement("span",{className:"logo-separator"},"|")," Mr. Bitcoin"))),r.a.createElement("div",{className:"login-container nav-item"},r.a.createElement(ue.a,{className:"nav-link",to:"/login"},r.a.createElement("img",{className:"login-img",alt:"login",src:ge.a})))))}));var he=function(){return r.a.createElement("div",{className:"App"},r.a.createElement(l.b,{history:m},r.a.createElement(fe,null),r.a.createElement(l.c,null,r.a.createElement(l.a,{path:"/",component:F,exact:!0}),r.a.createElement(l.a,{path:"/",component:y,exact:!0}),r.a.createElement(l.a,{path:"/about",component:y,exact:!0}),r.a.createElement(l.a,{path:"/login",component:R,exact:!0}),r.a.createElement(l.a,{path:"/contacts",component:oe,exact:!0}),r.a.createElement(l.a,{path:"/contact/:id",component:le,exact:!0}))))};Boolean("localhost"===window.location.hostname||"[::1]"===window.location.hostname||window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/));var ve=n(19),be=n(69),Ae=null;sessionStorage.user&&(Ae=JSON.parse(sessionStorage.user));var we={loggedInUser:Ae,users:[]},Ce={isLoading:!1},Ee={contacts:[],selectedContact:{}},ye={rate:0},Oe=Object(ve.c)({system:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:Ce,t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};switch(t.type){case"LOADING_START":return Object(p.a)({},e,{isLoading:!0});case"LOADING_DONE":return Object(p.a)({},e,{isLoading:!1});default:return e}},user:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:we,t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};switch(t.type){case"SET_USER":return Object(p.a)({},e,{loggedInUser:t.user});case"USER_REMOVE":return Object(p.a)({},e,{users:e.users.filter((function(e){return e._id!==t.userId}))});case"SET_USERS":return Object(p.a)({},e,{users:t.users});default:return e}},contact:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:Ee,t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};switch(t.type){case"SET_CONTACTS":return Object(p.a)({},e,{contacts:t.contacts});case"SET_SELECTED_CONTACT":return Object(p.a)({},e,{selectedContact:t.contact});case"CONTACT_ADD":return Object(p.a)({},e,{contacts:[].concat(Object(g.a)(e.contacts),[t.contact])});case"CONTACT_UPDATE":return Object(p.a)({},e,{contacts:e.contacts.map((function(e){return e._id===t.contact._id?t.contact:e}))});default:return e}},bitcoin:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:ye,t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};switch(t.type){case"SET_RATE":return Object(p.a)({},e,{rate:t.rate});default:return e}}}),xe=window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__||ve.d,Se=Object(ve.e)(Oe,xe(Object(ve.a)(be.a)));s.a.render(r.a.createElement(i.a,{store:Se},r.a.createElement(he,null)),document.getElementById("root")),"serviceWorker"in navigator&&navigator.serviceWorker.ready.then((function(e){e.unregister()}))},39:function(e,t,n){e.exports=n.p+"static/media/bitcoin-small.4cd3bf5d.png"},66:function(e,t){e.exports="data:image/png;base64,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"},67:function(e,t,n){e.exports=n.p+"static/media/login.6af14d7c.png"},70:function(e,t,n){e.exports=n(138)},79:function(e,t,n){},80:function(e,t,n){}},[[70,1,2]]]);
//# sourceMappingURL=main.2fe5aff0.chunk.js.map