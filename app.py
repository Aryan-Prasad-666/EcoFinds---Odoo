from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecofinds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER_USERS'] = 'static/uploads/users'
app.config['UPLOAD_FOLDER_PRODUCTS'] = 'static/uploads/products'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
db = SQLAlchemy(app)

# Ensure upload folders exist
os.makedirs(app.config['UPLOAD_FOLDER_USERS'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER_PRODUCTS'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    image = db.Column(db.String(200), default='user_image.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('products', lazy=True))
    images = db.relationship('ProductImage', backref='product', lazy=True, cascade='all, delete-orphan')

class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    image_path = db.Column(db.String(200), nullable=False)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('purchases', lazy=True))
    product = db.relationship('Product', backref=db.backref('purchases', lazy=True))

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))

# Create database
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        
        if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
            flash('Email or username already exists')
            return redirect(url_for('register'))
        
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            username=username
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        if request.form['password']:
            user.password_hash = generate_password_hash(request.form['password'])
        
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER_USERS'], filename)
                file.save(file_path)
                user.image = f'uploads/users/{filename}'
            elif file.filename:
                flash('Invalid file type. Please upload PNG, JPG, or JPEG.')
        
        db.session.commit()
        flash('Profile updated successfully')
        return redirect(url_for('dashboard'))
    
    return render_template('profile.html', user=user)

@app.route('/products/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Other']
    if request.method == 'POST':
        files = request.files.getlist('images')
        valid_files = [f for f in files if f and allowed_file(f.filename)]
        
        if len(valid_files) < 1:
            flash('At least one image is required (PNG, JPG, or JPEG).')
            return redirect(url_for('new_product'))
        if len(valid_files) > 10:
            flash('Maximum 10 images allowed.')
            return redirect(url_for('new_product'))
        
        product = Product(
            title=request.form['title'],
            description=request.form['description'],
            category=request.form['category'],
            price=float(request.form['price']),
            user_id=session['user_id']
        )
        db.session.add(product)
        db.session.flush()  # Get product ID before committing
        
        for file in valid_files:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER_PRODUCTS'], filename)
            file.save(file_path)
            product_image = ProductImage(product_id=product.id, image_path=f'uploads/products/{filename}')
            db.session.add(product_image)
        
        db.session.commit()
        flash('Product listed successfully')
        return redirect(url_for('dashboard'))
    
    return render_template('new_product.html', categories=categories)

@app.route('/products/<int:id>/edit', methods=['GET', 'POST'])
def edit_product(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(id)
    if product.user_id != session['user_id']:
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    
    categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Other']
    if request.method == 'POST':
        product.title = request.form['title']
        product.description = request.form['description']
        product.category = request.form['category']
        product.price = float(request.form['price'])
        
        # Handle image deletions
        delete_images = request.form.getlist('delete_images')
        for image_id in delete_images:
            image = ProductImage.query.get(image_id)
            if image and image.product_id == product.id:
                try:
                    os.remove(os.path.join(app.root_path, app.config['UPLOAD_FOLDER_PRODUCTS'], os.path.basename(image.image_path)))
                except FileNotFoundError:
                    pass
                db.session.delete(image)
        
        # Handle new image uploads
        files = request.files.getlist('images')
        valid_files = [f for f in files if f and allowed_file(f.filename)]
        current_image_count = len(product.images) - len(delete_images)
        
        if current_image_count + len(valid_files) < 1:
            flash('At least one image is required.')
            return redirect(url_for('edit_product', id=id))
        if current_image_count + len(valid_files) > 10:
            flash('Maximum 10 images allowed.')
            return redirect(url_for('edit_product', id=id))
        
        for file in valid_files:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER_PRODUCTS'], filename)
            file.save(file_path)
            product_image = ProductImage(product_id=product.id, image_path=f'uploads/products/{filename}')
            db.session.add(product_image)
        
        db.session.commit()
        flash('Product updated successfully')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_product.html', product=product, categories=categories)

@app.route('/products/<int:id>/delete', methods=['POST'])
def delete_product(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(id)
    if product.user_id != session['user_id']:
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    
    # Delete associated images from filesystem
    for image in product.images:
        try:
            os.remove(os.path.join(app.root_path, app.config['UPLOAD_FOLDER_PRODUCTS'], os.path.basename(image.image_path)))
        except FileNotFoundError:
            pass
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/products')
def browse_products():
    category = request.args.get('category')
    search = request.args.get('search')
    
    query = Product.query
    if category:
        query = query.filter_by(category=category)
    if search:
        query = query.filter(Product.title.ilike(f'%{search}%'))
    
    products = query.all()
    categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Other']
    return render_template('browse_products.html', products=products, categories=categories)

@app.route('/products/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    return render_template('product_detail.html', product=product)

@app.route('/purchases')
def purchases():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    purchases = Purchase.query.filter_by(user_id=session['user_id']).all()
    return render_template('purchases.html', purchases=purchases)

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cart_items = Cart.query.filter_by(user_id=session['user_id']).all()
    return render_template('cart.html', cart_items=cart_items)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cart_item = Cart(user_id=session['user_id'], product_id=product_id)
    db.session.add(cart_item)
    db.session.commit()
    flash('Product added to cart')
    return redirect(url_for('browse_products'))

@app.route('/cart/remove/<int:id>', methods=['POST'])
def remove_from_cart(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cart_item = Cart.query.get_or_404(id)
    if cart_item.user_id != session['user_id']:
        flash('Unauthorized')
        return redirect(url_for('cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    flash('Product removed from cart')
    return redirect(url_for('cart'))

@app.route('/purchase/<int:product_id>', methods=['POST'])
def purchase_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    purchase = Purchase(user_id=session['user_id'], product_id=product_id)
    db.session.add(purchase)
    db.session.commit()
    flash('Product purchased successfully')
    return redirect(url_for('purchases'))

if __name__ == '__main__':
    app.run(debug=True)