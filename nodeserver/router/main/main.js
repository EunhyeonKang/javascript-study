var express = require('express');
var app = express()
var path = require('path');
var router = express.Router();

router.get('/', function(req,res){
    console.log('main js loaded')
	res.sendFile(path.join(__dirname, '../public/main.html'))
});

module.exports = router;