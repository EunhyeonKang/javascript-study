import React, { Component } from 'react';
import facebookLogin from 'react-facebook-login';

export default class facebook extends Component {
    state = {
        isLoggedIn: false,
        userID: '',
        name: '',
        email: '',
        picture: ''
    };

    responseFacebook = response => {
        console.log('response');
    }

    componentClicked = () => console.log("clicked");

    render() {
        let fbContent;

        if(this.state.isLoggedIn){
            fbContent :null;
        }else{
            fbContent =(
                <FacebookLogin
                appId="574280399824524"
                autoLoad={true}
                fields="name,email,picture"
                onClick={this.componentClicked}
                callback={this.responseFacebook} />
                );
            }
        
        return <div>{fbContent}</div>;
        
    }
}
