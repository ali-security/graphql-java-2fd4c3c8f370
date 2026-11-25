package graphql.collect

import com.google.common.collect.BiMap
import com.google.common.collect.HashBiMap
import com.google.common.collect.LinkedHashMultimap
import com.google.common.collect.SetMultimap
import groovy.transform.CompileStatic
import spock.lang.Specification

import java.lang.reflect.Field
import java.util.function.BiFunction

/**
 * Guava is shaded into the graphql-java jar (relocated to graphql.com.google.common), so the
 * Guava version used by the build decides which Guava fixes ship with graphql-java.
 *
 * CVE-2026-118042 (GHSA-v5x9-67m3-7m56): HashBiMap and LinkedHashMultimap chained colliding entries
 * in their own hash buckets, so keys or values with equal hash codes made every lookup linear and
 * building the collection quadratic. graphql-java uses both of them for schema diffing and schema
 * transformation.
 *
 * Like Guava's AbstractHashFloodingTest, the flooding tests count the hashCode, equals and compareTo
 * calls for 2^10 and 2^15 colliding elements and require n log n growth to build the collection and
 * log n growth for a lookup, allowing up to 2x wobble in the constant factors.
 */
class ShadedGuavaHashFloodingTest extends Specification {

    private static final Map<String, Closure<BiMap>> BIMAP_CONSTRUCTIONS = [
            "colliding keys"                              : { List keys ->
                BiMap biMap = HashBiMap.create()
                for (Object key : keys) {
                    biMap.put(key, new Object())
                }
                return biMap
            },
            "colliding values"                            : { List values ->
                BiMap biMap = HashBiMap.create()
                for (Object value : values) {
                    biMap.put(new Object(), value)
                }
                return biMap
            },
            "colliding keys and values"                   : { List keysAndValues ->
                BiMap biMap = HashBiMap.create()
                for (Object keyAndValue : keysAndValues) {
                    biMap.put(keyAndValue, keyAndValue)
                }
                return biMap
            },
            "colliding values through replaceAll"         : { List values ->
                BiMap biMap = HashBiMap.create()
                for (int i = 0; i < values.size(); i++) {
                    biMap.put(new Object(), new Object())
                }
                Iterator valuesIterator = values.iterator()
                biMap.replaceAll({ k, v -> valuesIterator.next() } as BiFunction)
                return biMap
            },
            "colliding keys through inverse replaceAll"   : { List keys ->
                BiMap biMap = HashBiMap.create()
                for (int i = 0; i < keys.size(); i++) {
                    biMap.put(new Object(), new Object())
                }
                Iterator keysIterator = keys.iterator()
                biMap.inverse().replaceAll({ v, k -> keysIterator.next() } as BiFunction)
                return biMap
            },
            "colliding values through entry setValue"     : { List values ->
                BiMap biMap = HashBiMap.create()
                for (int i = 0; i < values.size(); i++) {
                    biMap.put(new Object(), new Object())
                }
                Iterator valuesIterator = values.iterator()
                for (Map.Entry entry : biMap.entrySet()) {
                    entry.setValue(valuesIterator.next())
                }
                return biMap
            },
            "colliding keys through inverse entry setValue": { List keys ->
                BiMap biMap = HashBiMap.create()
                for (int i = 0; i < keys.size(); i++) {
                    biMap.put(new Object(), new Object())
                }
                Iterator keysIterator = keys.iterator()
                for (Map.Entry entry : biMap.inverse().entrySet()) {
                    entry.setValue(keysIterator.next())
                }
                return biMap
            },
    ]

    private static final Map<String, Closure> BIMAP_QUERIES = [
            "get"        : { BiMap biMap, Object key -> biMap.get(key) },
            "inverse get": { BiMap biMap, Object value -> biMap.inverse().get(value) },
    ]

    private static final Map<String, Closure<SetMultimap>> MULTIMAP_CONSTRUCTIONS = [
            "colliding keys"  : { List keys ->
                SetMultimap multimap = LinkedHashMultimap.create()
                for (Object key : keys) {
                    multimap.put(key, new Object())
                }
                return multimap
            },
            "colliding values": { List values ->
                SetMultimap multimap = LinkedHashMultimap.create()
                for (Object value : values) {
                    multimap.put("key", value)
                }
                return multimap
            },
    ]

    private static final Map<String, Closure> MULTIMAP_QUERIES = [
            "containsKey" : { SetMultimap multimap, Object key -> multimap.containsKey(key) },
            "get contains": { SetMultimap multimap, Object value -> multimap.get("key").contains(value) },
    ]

    def "building a HashBiMap from #pathway is not quadratic"() {
        given:
        def smallCounter = new CallsCounter()
        def small = collidingKeys(10, smallCounter)
        def largeCounter = new CallsCounter()
        def large = collidingKeys(15, largeCounter)
        def construction = BIMAP_CONSTRUCTIONS[pathway]

        when:
        smallCounter.zero()
        construction.call(small)
        long smallOps = smallCounter.total()
        largeCounter.zero()
        BiMap biMap = construction.call(large)
        long largeOps = largeCounter.total()

        then:
        biMap.size() == large.size()
        (double) largeOps / smallOps <= 2 * nLogN(large.size()) / nLogN(small.size())

        where:
        pathway << (BIMAP_CONSTRUCTIONS.keySet() as List)
    }

    def "HashBiMap #query stays logarithmic on a map built from #pathway"() {
        given:
        def smallCounter = new CallsCounter()
        def small = collidingKeys(10, smallCounter)
        def largeCounter = new CallsCounter()
        def large = collidingKeys(15, largeCounter)

        when:
        long smallOps = worstCaseQueryOps(smallCounter, small, BIMAP_CONSTRUCTIONS[pathway], BIMAP_QUERIES[query])
        long largeOps = worstCaseQueryOps(largeCounter, large, BIMAP_CONSTRUCTIONS[pathway], BIMAP_QUERIES[query])

        then:
        (double) largeOps / smallOps <= 2 * Math.log(large.size()) / Math.log(small.size())

        where:
        [query, pathway] << [BIMAP_QUERIES.keySet() as List, BIMAP_CONSTRUCTIONS.keySet() as List].combinations()
    }

    def "building a LinkedHashMultimap from #pathway is not quadratic"() {
        given:
        def smallCounter = new CallsCounter()
        def small = collidingKeys(10, smallCounter)
        def largeCounter = new CallsCounter()
        def large = collidingKeys(15, largeCounter)
        def construction = MULTIMAP_CONSTRUCTIONS[pathway]

        when:
        smallCounter.zero()
        construction.call(small)
        long smallOps = smallCounter.total()
        largeCounter.zero()
        SetMultimap multimap = construction.call(large)
        long largeOps = largeCounter.total()

        then:
        multimap.size() == large.size()
        (double) largeOps / smallOps <= 2 * nLogN(large.size()) / nLogN(small.size())

        where:
        pathway << (MULTIMAP_CONSTRUCTIONS.keySet() as List)
    }

    def "LinkedHashMultimap #query stays logarithmic on a multimap built from #pathway"() {
        given:
        def smallCounter = new CallsCounter()
        def small = collidingKeys(10, smallCounter)
        def largeCounter = new CallsCounter()
        def large = collidingKeys(15, largeCounter)

        when:
        long smallOps = worstCaseQueryOps(smallCounter, small, MULTIMAP_CONSTRUCTIONS[pathway], MULTIMAP_QUERIES[query])
        long largeOps = worstCaseQueryOps(largeCounter, large, MULTIMAP_CONSTRUCTIONS[pathway], MULTIMAP_QUERIES[query])

        then:
        (double) largeOps / smallOps <= 2 * Math.log(large.size()) / Math.log(small.size())

        where:
        [query, pathway] << [MULTIMAP_QUERIES.keySet() as List, MULTIMAP_CONSTRUCTIONS.keySet() as List].combinations()
    }

    def "a HashBiMap of colliding keys and values switches to flooding resistant tables and stays a correct bimap"() {
        given:
        // 64 strings with the same hash code, well above the bucket length that triggers the switch
        List<String> keys = collidingStrings(6)
        List<String> values = keys.collect { "value-" + it }
        HashBiMap<String, String> biMap = HashBiMap.create()

        when:
        for (int i = 0; i < keys.size(); i++) {
            biMap.put(keys[i], keys[(i + 1) % keys.size()])
        }

        then:
        floodedTables(biMap) != null
        biMap.size() == 64
        (0..<64).every { biMap.get(keys[it]) == keys[(it + 1) % 64] }
        (0..<64).every { biMap.inverse().get(keys[(it + 1) % 64]) == keys[it] }
        (biMap.keySet() as List) == keys

        when: "refilling the cleared map with other colliding values"
        biMap.clear()
        for (int i = 0; i < keys.size(); i++) {
            biMap.put(keys[i], values[i])
        }

        then:
        floodedTables(biMap) != null
        (0..<64).every { biMap.get(keys[it]) == values[it] && biMap.inverse().get(values[it]) == keys[it] }

        when:
        biMap.put("other", values[3])

        then:
        thrown(IllegalArgumentException)

        when: "removing, force putting and putting through the inverse"
        biMap.remove(keys[0])
        biMap.forcePut(keys[1], values[2])
        biMap.inverse().put("new", keys[0])

        then:
        biMap.size() == 63
        !biMap.containsKey(keys[2])
        !biMap.containsValue(values[1])
        biMap.get(keys[1]) == values[2]
        biMap.inverse().get(values[2]) == keys[1]
        biMap.get(keys[0]) == "new"
        biMap.inverse().get("new") == keys[0]
        (biMap.keySet() as List) == [keys[1]] + keys[3..63] + [keys[0]]
        (biMap.inverse().keySet() as List) == [values[2]] + values[3..63] + ["new"]

        when: "removing through the entry set iterator"
        def iterator = biMap.entrySet().iterator()
        while (iterator.hasNext()) {
            if (iterator.next().getKey() == keys[10]) {
                iterator.remove()
            }
        }

        then:
        biMap.size() == 62
        !biMap.containsKey(keys[10])
        !biMap.inverse().containsKey(values[10])

        when: "serializing and deserializing the flooded map"
        HashBiMap<String, String> copy = (HashBiMap<String, String>) roundTrip(biMap)

        then:
        floodedTables(copy) != null
        copy == biMap
        (copy.keySet() as List) == (biMap.keySet() as List)
        copy.inverse() == biMap.inverse()
    }

    def "a LinkedHashMultimap value set of colliding values switches to a hash map and stays a correct set"() {
        given:
        // 64 strings with the same hash code, well above the bucket length that triggers the switch
        List<String> values = collidingStrings(6)
        LinkedHashMultimap<String, String> multimap = LinkedHashMultimap.create()

        when:
        for (String value : values) {
            multimap.put("key", value)
        }
        multimap.put("other", values[0])

        then:
        valueSetHashTable(multimap, "key") instanceof Map
        multimap.size() == 65
        (multimap.get("key") as List) == values
        values.every { multimap.containsEntry("key", it) }
        !multimap.put("key", values[3])
        multimap.size() == 65
        !multimap.containsEntry("key", "missing")

        when:
        multimap.remove("key", values[0])
        multimap.get("key").remove(values[10])

        then:
        multimap.size() == 63
        !multimap.containsEntry("key", values[0])
        !multimap.containsEntry("key", values[10])
        multimap.containsEntry("other", values[0])
        (multimap.get("key") as List) == values[1..9] + values[11..63]
        multimap.entries().last().getKey() == "other"

        when: "serializing and deserializing the flooded multimap"
        LinkedHashMultimap<String, String> copy = (LinkedHashMultimap<String, String>) roundTrip(multimap)

        then:
        valueSetHashTable(copy, "key") instanceof Map
        copy == multimap
        (copy.entries() as List) == (multimap.entries() as List)

        when:
        multimap.get("key").clear()

        then:
        !multimap.containsKey("key")
        multimap.size() == 1
        multimap.put("key", values[5])
        multimap.get("key") == [values[5]] as Set
    }

    /**
     * Returns 2^power strings that all have the same hash code: "Aa" and "BB" collide, and so does
     * every concatenation of the same number of them.
     */
    private static List<String> collidingStrings(int power) {
        List<String> strings = [""]
        for (int i = 0; i < power; i++) {
            strings = strings.collectMany { [it + "Aa", it + "BB"] }
        }
        assert strings.collect { it.hashCode() }.toSet().size() == 1
        return strings
    }

    private static List<CollidingKey> collidingKeys(int power, CallsCounter counter) {
        return collidingStrings(power).collect { new CollidingKey(it, counter) }
    }

    private static double nLogN(int n) {
        return n * Math.log(n)
    }

    private static long worstCaseQueryOps(CallsCounter counter, List<CollidingKey> keys, Closure construction, Closure query) {
        def collection = construction.call(keys)
        long worstOps = 0
        for (CollidingKey key : keys) {
            counter.zero()
            query.call(collection, key)
            worstOps = Math.max(worstOps, counter.total())
        }
        return worstOps
    }

    private static Object roundTrip(Object object) {
        def baos = new ByteArrayOutputStream()
        def oos = new ObjectOutputStream(baos)
        try {
            oos.writeObject(object)
        } finally {
            oos.close()
        }
        def ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))
        try {
            return ois.readObject()
        } finally {
            ois.close()
        }
    }

    // read the internals by reflection, Map instances turn Groovy property access into get(key)
    private static Object floodedTables(HashBiMap<?, ?> biMap) {
        return field(HashBiMap, "floodedTables").get(biMap)
    }

    private static Object valueSetHashTable(LinkedHashMultimap<?, ?> multimap, Object key) {
        Map<?, ?> backingMap = (Map<?, ?>) field(LinkedHashMultimap, "map").get(multimap)
        Object valueSet = backingMap.get(key)
        return field(valueSet.getClass(), "hashTable").get(valueSet)
    }

    private static Field field(Class<?> type, String name) {
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name)
                f.setAccessible(true)
                return f
            } catch (NoSuchFieldException ignored) {
                // keep looking in the superclass
            }
        }
        throw new NoSuchFieldException(name)
    }

    /** Counts the calls to hashCode, equals and compareTo of the CollidingKey instances it is given to. */
    @CompileStatic
    static final class CallsCounter {
        long hashCodeCalls
        long equalsCalls
        long compareToCalls

        long total() {
            return hashCodeCalls + equalsCalls + compareToCalls
        }

        void zero() {
            hashCodeCalls = 0
            equalsCalls = 0
            compareToCalls = 0
        }
    }

    /** A Comparable wrapper around a String that counts the calls to hashCode, equals and compareTo. */
    @CompileStatic
    static final class CollidingKey implements Comparable<CollidingKey> {
        private final String value
        private final CallsCounter counter

        CollidingKey(String value, CallsCounter counter) {
            this.value = value
            this.counter = counter
        }

        @Override
        int hashCode() {
            counter.hashCodeCalls++
            return value.hashCode()
        }

        @Override
        boolean equals(Object other) {
            counter.equalsCalls++
            return other instanceof CollidingKey && value.equals(((CollidingKey) other).value)
        }

        @Override
        int compareTo(CollidingKey other) {
            counter.compareToCalls++
            return value.compareTo(other.value)
        }

        @Override
        String toString() {
            return value
        }
    }
}
