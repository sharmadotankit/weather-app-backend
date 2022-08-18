import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import bodyParser from 'body-parser';
import knex from 'knex';
import jwt from 'jsonwebtoken';
import {SECRET_KEY} from './secretKey.js';


const db = knex({
	client:'pg',
	connection:{
		host:'127.0.0.1',
		user:'postgres',
		password:'postgres',
		database:'weather-app'
	}
});


const app = express();
const saltRounds = 10;

app.use(bodyParser.json());
app.use(cors());
app.use(express.json());

app.get('/',(req,res)=>{
	res.send("<h1>HelloWorld</h1>");
});


app.post('/signin',(req,res)=>{
	const {email,password} = req.body;
	db.select('email','hash')
	.from('login')
	.where('email','=', email)
	.then(data=>
		{
			const isValid = bcrypt.compareSync(password, data[0].hash);
			if(isValid){
				return db.select('*')
				.from('users')
				.where('email','=',email)
				.then(user=>{
					jwt.sign({user: user[0]},SECRET_KEY,(err,token)=>{
						const validatedUser = Object.assign({},user[0],{token:token});
						res.json(validatedUser);
					})
				})
				.catch(err => res.status(400).json('Unable to get user'));
			}
			else{
				res.status(400).json('Wrong credentials');
			}
		}).catch(err => res.status(400).json('Wrong credentials'));
});

app.post('/register',(req,res)=>{
	const {name,email,password}=req.body;

	const passwordHash = bcrypt.hashSync(password, saltRounds, function(err, hash) {
		return hash;
	});

	db.transaction(trx=>{
		trx.insert({
			hash:passwordHash,
			email:email
		})
		.into('login')
		.returning('email')
		.then(loginEmail =>{
			return  trx('users')
					.returning('*')
					.insert({
						name:name,
						email:loginEmail[0].email
					})
					.then(user=>{
						jwt.sign({user: user[0]},SECRET_KEY,(err,token)=>{
						const validatedUser = Object.assign({},user[0],{token:token});
						res.json(validatedUser);
						})
					})
					.then(trx.commit)
					.catch(trx.rollback)
		}).catch(err=> res.status(400).json('Unable to register'));
	}).catch(err=> res.status(400).json('Unable to register'));
});


app.put('/counter',verifyToken,(req,res)=>{
	let {id} = req.body;
	jwt.verify(req.token,SECRET_KEY,(err,authData)=>{
		if(err){
			res.status(403).json('Something went wrong!');
		}else{
			db('users').where('id','=',id)
			.increment('count',1)
			.returning('count')
			.then(count =>{
				res.json(count[0].count);
			}).catch(err => res.status(400).json('Unable to get the entries'))
		}
	})
})


// verifyToken

function verifyToken (req,res,next){
	const bearerHeader = req.headers['authorization'];
	if(typeof bearerHeader !== 'undefined'){
		const bearer = bearerHeader.split(' ');
		const bearerToken = bearer[1];
		req.token = bearerToken;
		next();
	}
	else{
		res.json('Forbidden');
	}
}





app.listen(5000,()=>{ console.log("app is running in port 5000")});
