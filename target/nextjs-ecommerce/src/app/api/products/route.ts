import { NextRequest, NextResponse } from 'next/server';

// Simulated product database
const products = [
  {
    id: '1', name: 'Premium Wireless Headphones', category: 'Electronics',
    price: 299.99, originalPrice: 399.99, rating: 4.8, reviewCount: 1247,
    description: 'Experience premium sound quality with active noise cancellation and 30-hour battery life.',
    images: ['main', 'side', 'back'], variants: { colors: ['Black', 'White', 'Blue'], sizes: [] },
    stock: 15, badge: 'SALE', emoji: '🎧'
  },
  {
    id: '2', name: 'Smart Fitness Watch Pro', category: 'Electronics',
    price: 249.99, rating: 4.6, reviewCount: 892,
    description: 'Track your health metrics, GPS, heart rate monitor, and 7-day battery life.',
    images: ['main', 'side'], variants: { colors: ['Black', 'Silver', 'Rose Gold'], sizes: ['S', 'M', 'L'] },
    stock: 8, badge: 'NEW', emoji: '⌚'
  },
  {
    id: '3', name: 'Ergonomic Office Chair', category: 'Furniture',
    price: 549.99, originalPrice: 699.99, rating: 4.9, reviewCount: 567,
    description: 'Adjustable lumbar support, breathable mesh back, and premium build quality.',
    images: ['main', 'side', 'detail'], variants: { colors: ['Black', 'Gray'], sizes: [] },
    stock: 3, emoji: '🪑'
  },
  {
    id: '4', name: 'Minimalist Backpack', category: 'Accessories',
    price: 89.99, rating: 4.5, reviewCount: 2341,
    description: 'Water-resistant material, laptop compartment, and multiple pockets.',
    images: ['main', 'back'], variants: { colors: ['Black', 'Navy', 'Gray', 'Green'], sizes: [] },
    stock: 50, emoji: '🎒'
  },
  {
    id: '5', name: 'Mechanical Keyboard RGB', category: 'Electronics',
    price: 159.99, rating: 4.7, reviewCount: 1893,
    description: 'Cherry MX switches, full RGB backlighting, and aluminum frame.',
    images: ['main', 'side'], variants: { colors: ['Black', 'White'], sizes: [] },
    stock: 25, badge: 'BESTSELLER', emoji: '⌨️'
  },
  {
    id: '6', name: 'Ultra-Slim Laptop Stand', category: 'Accessories',
    price: 79.99, originalPrice: 99.99, rating: 4.4, reviewCount: 678,
    description: 'Aluminum construction, foldable design, and universal compatibility.',
    images: ['main'], variants: { colors: ['Silver', 'Space Gray'], sizes: [] },
    stock: 42, emoji: '💻'
  },
  {
    id: '7', name: 'Noise Cancelling Earbuds', category: 'Electronics',
    price: 179.99, rating: 4.6, reviewCount: 3421,
    description: 'Compact design, 8-hour battery, and wireless charging case.',
    images: ['main', 'case'], variants: { colors: ['White', 'Black'], sizes: [] },
    stock: 0, emoji: '🎵'
  },
  {
    id: '8', name: 'Designer Desk Lamp', category: 'Furniture',
    price: 129.99, rating: 4.3, reviewCount: 456,
    description: 'Adjustable brightness, color temperature control, and USB charging port.',
    images: ['main'], variants: { colors: ['White', 'Black', 'Wood'], sizes: [] },
    stock: 18, emoji: '💡'
  },
];

export async function GET(request: NextRequest) {
  // Simulate network latency
  await new Promise(resolve => setTimeout(resolve, 200));

  const { searchParams } = new URL(request.url);
  const category = searchParams.get('category');
  const search = searchParams.get('search');
  const minPrice = searchParams.get('minPrice');
  const maxPrice = searchParams.get('maxPrice');
  const inStock = searchParams.get('inStock');
  const sortBy = searchParams.get('sortBy');
  const page = parseInt(searchParams.get('page') || '1');
  const limit = parseInt(searchParams.get('limit') || '10');

  let filtered = [...products];

  // Apply filters
  if (category && category !== 'All') {
    filtered = filtered.filter(p => p.category === category);
  }

  if (search) {
    const searchLower = search.toLowerCase();
    filtered = filtered.filter(p =>
      p.name.toLowerCase().includes(searchLower) ||
      p.description.toLowerCase().includes(searchLower)
    );
  }

  if (minPrice) {
    filtered = filtered.filter(p => p.price >= parseFloat(minPrice));
  }

  if (maxPrice) {
    filtered = filtered.filter(p => p.price <= parseFloat(maxPrice));
  }

  if (inStock === 'true') {
    filtered = filtered.filter(p => p.stock > 0);
  }

  // Apply sorting
  if (sortBy) {
    switch (sortBy) {
      case 'price-low':
        filtered.sort((a, b) => a.price - b.price);
        break;
      case 'price-high':
        filtered.sort((a, b) => b.price - a.price);
        break;
      case 'rating':
        filtered.sort((a, b) => b.rating - a.rating);
        break;
      case 'newest':
        filtered.sort((a, b) => parseInt(b.id) - parseInt(a.id));
        break;
    }
  }

  // Pagination
  const total = filtered.length;
  const start = (page - 1) * limit;
  const paginated = filtered.slice(start, start + limit);

  return NextResponse.json({
    products: paginated,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasMore: start + limit < total
    }
  });
}

export async function POST(request: NextRequest) {
  // Create product (admin only - would need auth in real app)
  const body = await request.json();

  const newProduct = {
    id: (products.length + 1).toString(),
    ...body,
    rating: 0,
    reviewCount: 0,
  };

  products.push(newProduct);

  return NextResponse.json({ product: newProduct }, { status: 201 });
}
