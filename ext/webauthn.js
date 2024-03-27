const browserCredentials = {
  create: navigator.credentials.create.bind(
	navigator.credentials,
  ),
  get: navigator.credentials.get.bind(navigator.credentials),
};

//const messenger = ((window as any).messenger = Messenger.forDOMCommunication(window));

//navigator.credentials.create = function() {
//	console.log("CREATE OVERRIDE \\o/");
//};
//navigator.credentials.get = function() {
//	console.log("GET OVERRIDE \\o/");
//};
