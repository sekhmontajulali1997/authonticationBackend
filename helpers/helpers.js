// create a rondom number

export const generateOTP = ()=> {
    return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
  }
  
