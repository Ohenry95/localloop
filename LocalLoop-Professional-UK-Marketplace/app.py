import os, secrets, re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import stripe

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=os.environ.get('LOCALLOOP_SECRET_KEY') or 'dev-only-change-me-before-deploy',
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///localloop.db').replace('postgres://','postgresql://',1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('LOCALLOOP_ENV') == 'production',
    MAX_CONTENT_LENGTH=2_000_000,
)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
COMMISSION_PERCENT = 15
CATEGORIES = ['Food & Drink','Things to Do','Beauty & Wellness','Shopping','Services','Other']

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash=db.Column(db.String(255), nullable=False)
    name=db.Column(db.String(100), nullable=False)
    role=db.Column(db.String(20), nullable=False, default='customer')
    created_at=db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    business=db.relationship('Business', backref='owner', uselist=False)

class Business(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    name=db.Column(db.String(120), nullable=False)
    description=db.Column(db.String(2000), nullable=False, default='')
    town=db.Column(db.String(100), nullable=False)
    contact_email=db.Column(db.String(254), nullable=False)
    status=db.Column(db.String(20), nullable=False, default='pending')
    stripe_account_id=db.Column(db.String(255), unique=True)
    stripe_charges_enabled=db.Column(db.Boolean, nullable=False, default=False)

class Deal(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    business_id=db.Column(db.Integer, db.ForeignKey('business.id'), nullable=False)
    title=db.Column(db.String(140), nullable=False)
    description=db.Column(db.String(3000), nullable=False)
    category=db.Column(db.String(50), nullable=False)
    price_pence=db.Column(db.Integer, nullable=False)
    original_price_pence=db.Column(db.Integer, nullable=False)
    town=db.Column(db.String(100), nullable=False)
    quantity=db.Column(db.Integer, nullable=False)
    remaining=db.Column(db.Integer, nullable=False)
    status=db.Column(db.String(20), nullable=False, default='pending')
    created_at=db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    business=db.relationship('Business', backref='deals')

class Booking(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    deal_id=db.Column(db.Integer, db.ForeignKey('deal.id'), nullable=False)
    code=db.Column(db.String(24), unique=True, nullable=False)
    status=db.Column(db.String(20), nullable=False, default='pending_payment')
    amount_pence=db.Column(db.Integer, nullable=False)
    stripe_session_id=db.Column(db.String(255), unique=True)
    created_at=db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user=db.relationship('User', backref='bookings')
    deal=db.relationship('Deal')

class StripeEvent(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    event_id=db.Column(db.String(255), unique=True, nullable=False)
    event_type=db.Column(db.String(120), nullable=False)
    received_at=db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

with app.app_context():
    db.create_all()

@app.before_request
def require_real_secrets():
    if os.environ.get('LOCALLOOP_ENV') == 'production':
        if not os.environ.get('LOCALLOOP_SECRET_KEY') or len(os.environ.get('LOCALLOOP_SECRET_KEY','')) < 32:
            raise RuntimeError('Set LOCALLOOP_SECRET_KEY to a random value of at least 32 characters.')

@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    return response

def current_user():
    uid=session.get('uid')
    return db.session.get(User, uid) if uid else None

@app.context_processor
def context():
    return {'me':current_user(), 'categories':CATEGORIES, 'commission_percent':COMMISSION_PERCENT,
            'current_year': datetime.now(timezone.utc).year,
            'money':lambda p: '£{:,.2f}'.format((p or 0)/100)}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash('Please sign in first.'); return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            u=current_user()
            if not u: return redirect(url_for('login'))
            if u.role not in roles: abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def valid_email(email): return bool(re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email or ''))
def pence(value):
    try:
        d=Decimal(value)
        if not d.is_finite() or d <= 0 or d > Decimal('100000'): return None
        return int((d*100).quantize(Decimal('1'),rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError, TypeError): return None

def payment_ready(business):
    return bool(stripe.api_key and business and business.stripe_account_id and business.stripe_charges_enabled)

@app.get('/')
def home():
    q=request.args.get('q','').strip()[:100]; town=request.args.get('town','').strip()[:100]; cat=request.args.get('category','')
    query=Deal.query.filter_by(status='approved').filter(Deal.remaining>0)
    if q: query=query.filter(db.or_(Deal.title.ilike(f'%{q}%'), Deal.description.ilike(f'%{q}%')))
    if town: query=query.filter(Deal.town.ilike(f'%{town}%'))
    if cat in CATEGORIES: query=query.filter_by(category=cat)
    return render_template('home.html', deals=query.order_by(Deal.created_at.desc()).limit(100).all(), q=q, town=town, category=cat)

@app.get('/deal/<int:deal_id>')
def deal_page(deal_id):
    deal=Deal.query.filter_by(id=deal_id,status='approved').first_or_404()
    return render_template('deal.html',deal=deal)

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form.get('name','').strip()[:100]; email=request.form.get('email','').strip().lower()[:254]; password=request.form.get('password','')
        if not name or not valid_email(email) or len(password)<12 or len(password)>256:
            flash('Enter a valid name and email. Use a password of at least 12 characters.')
        elif User.query.filter_by(email=email).first(): flash('An account with that email already exists.')
        else:
            role='admin' if email == os.environ.get('ADMIN_EMAIL','').strip().lower() and os.environ.get('ADMIN_EMAIL') else 'customer'
            user=User(name=name,email=email,password_hash=generate_password_hash(password),role=role)
            db.session.add(user); db.session.commit(); session.clear(); session['uid']=user.id; session['_csrf_token']=secrets.token_urlsafe(32)
            flash('Account created. Email verification must be configured before public launch.')
            return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        user=User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash,password):
            session.clear(); session['uid']=user.id; session['_csrf_token']=secrets.token_urlsafe(32)
            nxt=request.args.get('next','')
            return redirect(nxt if nxt.startswith('/') and not nxt.startswith('//') and '\\' not in nxt else url_for('home'))
        flash('Email or password was not recognised.')
    return render_template('login.html')

@app.post('/logout')
@login_required
def logout(): session.clear(); flash('Signed out.'); return redirect(url_for('home'))

@app.route('/business',methods=['GET','POST'])
@login_required
def business_dashboard():
    u=current_user(); b=Business.query.filter_by(user_id=u.id).first()
    if request.method=='POST':
        name=request.form.get('name','').strip()[:120]; town=request.form.get('town','').strip()[:100]; email=request.form.get('contact_email','').strip().lower()[:254]; desc=request.form.get('description','').strip()[:2000]
        if not name or not town or not valid_email(email): flash('Enter a business name, town and valid contact email.')
        elif b:
            b.name=name; b.town=town; b.contact_email=email; b.description=desc; b.status='pending'; db.session.commit(); flash('Business profile saved for review.')
        else:
            b=Business(user_id=u.id,name=name,town=town,contact_email=email,description=desc); db.session.add(b); db.session.commit(); flash('Business profile submitted for review.')
        return redirect(url_for('business_dashboard'))
    return render_template('business.html',business=b)

@app.post('/business/connect')
@login_required
def connect_stripe():
    b=Business.query.filter_by(user_id=current_user().id).first_or_404()
    if b.status!='verified': flash('Your business must be reviewed before connecting payouts.'); return redirect(url_for('business_dashboard'))
    if not stripe.api_key: flash('Payments are not configured yet. The site administrator must add Stripe keys securely.'); return redirect(url_for('business_dashboard'))
    try:
        if not b.stripe_account_id:
            account=stripe.Account.create(type='express',country='GB',email=b.contact_email,capabilities={'card_payments':{'requested':True},'transfers':{'requested':True}},metadata={'localloop_business_id':str(b.id)})
            b.stripe_account_id=account.id; db.session.commit()
        link=stripe.AccountLink.create(account=b.stripe_account_id,refresh_url=url_for('business_dashboard',_external=True),return_url=url_for('stripe_return',_external=True),type='account_onboarding')
        return redirect(link.url)
    except Exception as exc:
        app.logger.exception('Stripe Connect onboarding failed')
        flash('Stripe onboarding could not start. Check server logs and Stripe settings.'); return redirect(url_for('business_dashboard'))

@app.get('/stripe/return')
@login_required
def stripe_return():
    b=Business.query.filter_by(user_id=current_user().id).first_or_404()
    if b.stripe_account_id and stripe.api_key:
        try:
            acct=stripe.Account.retrieve(b.stripe_account_id); b.stripe_charges_enabled=bool(acct.get('charges_enabled')); db.session.commit()
        except Exception: app.logger.exception('Could not refresh Connect account status')
    flash('Stripe onboarding returned. Account status is checked again when Stripe sends an update.')
    return redirect(url_for('business_dashboard'))

@app.post('/business/deal')
@login_required
def create_deal():
    b=Business.query.filter_by(user_id=current_user().id).first_or_404()
    if b.status!='verified': flash('Your business must be approved before adding deals.'); return redirect(url_for('business_dashboard'))
    title=request.form.get('title','').strip()[:140]; desc=request.form.get('description','').strip()[:3000]; cat=request.form.get('category',''); town=request.form.get('town','').strip()[:100]
    price=pence(request.form.get('price')); original=pence(request.form.get('original_price')); qty=request.form.get('quantity','')
    try: qty=int(qty)
    except ValueError: qty=0
    if not title or not desc or not town or cat not in CATEGORIES or price is None or original is None or original < price or not 1<=qty<=10000:
        flash('Check all fields. The original price must be greater than or equal to the deal price.'); return redirect(url_for('business_dashboard'))
    db.session.add(Deal(business_id=b.id,title=title,description=desc,category=cat,town=town,price_pence=price,original_price_pence=original,quantity=qty,remaining=qty,status='pending'))
    db.session.commit(); flash('Deal submitted for admin review.'); return redirect(url_for('business_dashboard'))

@app.post('/buy/<int:deal_id>')
@login_required
def buy(deal_id):
    deal=Deal.query.filter_by(id=deal_id,status='approved').first_or_404()
    if deal.remaining < 1: flash('This deal has sold out.'); return redirect(url_for('deal_page',deal_id=deal.id))
    if not stripe.api_key: flash('Online payments are not configured yet. No payment was taken.'); return redirect(url_for('deal_page',deal_id=deal.id))
    if not payment_ready(deal.business): flash('This business is not yet able to receive payments. Please try again later.'); return redirect(url_for('deal_page',deal_id=deal.id))
    # Reserve one unit before checkout; the expiry webhook releases it if checkout is abandoned.
    try:
        updated=Deal.query.filter(Deal.id==deal.id,Deal.remaining>0).update({Deal.remaining:Deal.remaining-1},synchronize_session=False)
        if not updated: db.session.rollback(); flash('This deal has sold out.'); return redirect(url_for('deal_page',deal_id=deal.id))
        booking=Booking(user_id=current_user().id,deal_id=deal.id,code=secrets.token_urlsafe(9).upper().replace('-','')[:16],status='pending_payment',amount_pence=deal.price_pence)
        db.session.add(booking); db.session.commit()
        fee=(deal.price_pence*COMMISSION_PERCENT)//100
        checkout=stripe.checkout.Session.create(mode='payment',payment_method_types=['card'],line_items=[{'price_data':{'currency':'gbp','product_data':{'name':deal.title,'description':f'{deal.business.name} · {deal.town}'},'unit_amount':deal.price_pence},'quantity':1}],
            payment_intent_data={'application_fee_amount':fee,'transfer_data':{'destination':deal.business.stripe_account_id}},
            success_url=url_for('payment_success',_external=True)+'?session_id={CHECKOUT_SESSION_ID}',cancel_url=url_for('deal_page',deal_id=deal.id,_external=True),metadata={'booking_id':str(booking.id),'deal_id':str(deal.id),'user_id':str(current_user().id)})
        booking.stripe_session_id=checkout.id; db.session.commit()
        return redirect(checkout.url,code=303)
    except Exception:
        db.session.rollback(); app.logger.exception('Checkout creation failed')
        # Best-effort release for a reservation whose checkout could not be created.
        if 'booking' in locals() and booking.id:
            Booking.query.filter_by(id=booking.id,status='pending_payment').delete(); Deal.query.filter_by(id=deal.id).update({Deal.remaining:Deal.remaining+1}); db.session.commit()
        flash('Checkout could not be started. No successful payment is recorded.'); return redirect(url_for('deal_page',deal_id=deal.id))

@app.get('/payment/success')
@login_required
def payment_success():
    sid=request.args.get('session_id','')
    booking=Booking.query.filter_by(stripe_session_id=sid,user_id=current_user().id).first()
    if not booking: abort(404)
    # Webhook is authoritative; do not trust the success redirect as proof of payment.
    flash('Thanks! Your payment is being confirmed. Refresh My bookings in a moment if the voucher is not shown yet.')
    return redirect(url_for('my_bookings'))

@app.post('/stripe/webhook')
@csrf.exempt
def stripe_webhook():
    secret=os.environ.get('STRIPE_WEBHOOK_SECRET','')
    if not secret or not stripe.api_key: return jsonify(error='webhook_not_configured'),503
    payload=request.get_data(); signature=request.headers.get('Stripe-Signature','')
    try: event=stripe.Webhook.construct_event(payload,signature,secret)
    except Exception: return jsonify(error='invalid_signature'),400
    if StripeEvent.query.filter_by(event_id=event.id).first(): return jsonify(received=True),200
    obj=event.data.object
    if event.type=='checkout.session.completed' and obj.get('payment_status')=='paid':
        booking_id=(obj.get('metadata') or {}).get('booking_id')
        booking=db.session.get(Booking,int(booking_id)) if booking_id and str(booking_id).isdigit() else None
        if booking and booking.status=='pending_payment' and booking.stripe_session_id==obj.id: booking.status='paid'
    elif event.type=='checkout.session.expired':
        booking_id=(obj.get('metadata') or {}).get('booking_id')
        booking=db.session.get(Booking,int(booking_id)) if booking_id and str(booking_id).isdigit() else None
        if booking and booking.status=='pending_payment':
            booking.status='expired'; booking.deal.remaining+=1
    db.session.add(StripeEvent(event_id=event.id,event_type=event.type)); db.session.commit()
    return jsonify(received=True),200

@app.get('/my-bookings')
@login_required
def my_bookings():
    bookings=Booking.query.filter_by(user_id=current_user().id).order_by(Booking.created_at.desc()).all()
    return render_template('bookings.html',bookings=bookings)

@app.get('/admin')
@roles_required('admin')
def admin():
    businesses=Business.query.order_by(Business.id.desc()).all(); deals=Deal.query.filter_by(status='pending').order_by(Deal.id.desc()).all()
    return render_template('admin.html',businesses=businesses,deals=deals)

@app.post('/admin/business/<int:business_id>')
@roles_required('admin')
def moderate_business(business_id):
    b=db.get_or_404(Business,business_id); status=request.form.get('status')
    if status not in ('verified','rejected','pending'): abort(400)
    b.status=status; db.session.commit(); flash('Business review status updated.'); return redirect(url_for('admin'))

@app.post('/admin/deal/<int:deal_id>')
@roles_required('admin')
def moderate_deal(deal_id):
    d=db.get_or_404(Deal,deal_id); status=request.form.get('status')
    if status not in ('approved','rejected','pending'): abort(400)
    d.status=status; db.session.commit(); flash('Deal review status updated.'); return redirect(url_for('admin'))


@app.get('/robots.txt')
def robots_txt():
    """Keep account, admin and checkout journeys out of search indexes."""
    from flask import Response
    body = "User-agent: *\nAllow: /\nDisallow: /login\nDisallow: /register\nDisallow: /business\nDisallow: /my-bookings\nDisallow: /admin\nDisallow: /payment/\nSitemap: " + request.url_root.rstrip('/') + "/sitemap.xml\n"
    return Response(body, mimetype='text/plain')

@app.get('/sitemap.xml')
def sitemap_xml():
    """A small, current XML sitemap containing only public marketplace pages."""
    from flask import Response
    from xml.etree.ElementTree import Element, SubElement, tostring
    root_xml = Element('urlset', {'xmlns':'http://www.sitemaps.org/schemas/sitemap/0.9'})
    urls = [(url_for('home', _external=True), 'weekly', '1.0'),
            (url_for('terms', _external=True), 'yearly', '0.2'),
            (url_for('privacy', _external=True), 'yearly', '0.2')]
    for deal in Deal.query.filter_by(status='approved').filter(Deal.remaining > 0).all():
        urls.append((url_for('deal_page', deal_id=deal.id, _external=True), 'weekly', '0.7'))
    for loc, freq, priority in urls:
        item = SubElement(root_xml, 'url')
        SubElement(item, 'loc').text = loc
        SubElement(item, 'changefreq').text = freq
        SubElement(item, 'priority').text = priority
    return Response('<?xml version="1.0" encoding="UTF-8"?>' + tostring(root_xml, encoding='unicode'), mimetype='application/xml')

@app.get('/health')
def health(): return jsonify(status='ok',database='connected',stripe_configured=bool(stripe.api_key),commission_percent=COMMISSION_PERCENT)

@app.get('/terms')
def terms(): return render_template('legal.html',title='Terms of service',paragraphs=['This page is a draft for review, not a final legal contract. Before launch, get UK legal advice on marketplace roles, seller obligations, consumer rights, cancellations, refunds, voucher expiry, complaints, fees and dispute resolution.','A deal is not available until approved. Payments are processed by Stripe. LocalLoop targets a 15% platform fee on successful eligible transactions; the business receives the remainder subject to payment processing costs and the final seller agreement.'])
@app.get('/privacy')
def privacy(): return render_template('legal.html',title='Privacy notice',paragraphs=['This is a draft and must be reviewed before collecting real customer data. Specify the legal entity and contact details, lawful bases, retention periods, processors, international transfers and how people can exercise their rights.','Passwords are stored as password hashes. Payment card details are handled by Stripe Checkout and should never be collected directly by LocalLoop.'])
@app.errorhandler(403)
def forbidden(e): return render_template('error.html',code=403,message='You do not have permission to view this page.'),403
@app.errorhandler(404)
def missing(e): return render_template('error.html',code=404,message='We could not find that page.'),404

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=os.environ.get('LOCALLOOP_ENV')!='production')
