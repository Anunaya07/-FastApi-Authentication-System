import jwt
import fastapi
from fastapi import FastAPI , Depends , HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model
import os.path




# This is the FastAPI app.
app = FastAPI()
JWT_SECRET = 'SK'

pth = os.path.dirname(__file__)


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)
    
    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


User_Pydantic = pydantic_model_creator(User, name="User")
UserIn_Pydantic = pydantic_model_creator(User, name="UserIn", exclude_readonly= True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    
    if not user.verify_password(password):
        return False
    
    return user


    

@app.get("/",response_class=HTMLResponse)
def loginwithCreds(): 
    with open(os.path.join(pth, "templates/login.html")) as f:
        return HTMLResponse(content=f.read())

@app.get("/signUp",response_class=HTMLResponse)
def loginwithCreds(): 
    with open(os.path.join(pth, "templates/signUp.html")) as f:
        return HTMLResponse(content=f.read())

@app.post('/users') 
async def create_user(user: OAuth2PasswordRequestForm = Depends()): 
    user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)

@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    

    
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail= 'Invalid username or password'
            )
    
    
    user_obj = await User_Pydantic.from_tortoise_orm(user)
    
    token=jwt.encode(user_obj.dict(), JWT_SECRET)
    resp = RedirectResponse(url="/users/dashboard",status_code=status.HTTP_302_FOUND)
    print(resp)
    print({'access_token': token, 'token_type' : 'bearer', 'resp': resp})

    return fastapi.responses.RedirectResponse(
        '/user/dashboard', 
        status_code=status.HTTP_302_FOUND)

@app.get('/user/dashboard') 
async def get_user(): 
    return {"message":"welcome"}


    


# register_tortoise(

#         app,
#         db_url='sqlite://db.sqlite3',
#         modules = {'models': ['main']},
#         generate_schemas=True,
#         add_exception_handlers=True
    
# )